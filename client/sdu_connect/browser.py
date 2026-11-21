"""Browser-assisted CAS login.

Why this exists: SDU's ``/cas/device`` answers HTTP 500 for accounts it cannot
resolve (the real browser gets the same 500, so it is a server-side quirk, not a
client bug).  When that endpoint misbehaves for a real account too, the reliable
way through is to let a real browser render the CAS page -- its own JS computes
the fingerprint, handles the SMS dialog and any captcha -- and simply capture the
redirect to ``/passport/v1/auth/cas?ticket=...``.

The redirect is intercepted *before* it is sent, because a CAS ticket is
single-use: once the browser follows it, zju-connect can no longer spend it.
"""

from __future__ import annotations

import time
import json
import os
import tempfile
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

import requests

from .cas import CasError, ticket_from_url
from .config import config_dir


class BrowserUnavailable(CasError):
    pass


@dataclass
class BrowserResult:
    ticket: str
    cookies: list[dict]


def refresh_service_ticket(cas_url: str, cookies: list[dict]) -> str:
    """Mint a fresh CAS service ticket from the browser's session cookies.

    A CAS ticket is single-use.  When Chromium follows the gateway redirect the
    captured ticket is already spent, so ``complete_cas`` (or zju-connect) would
    see a callback without the client environment ticket.  The CAS ``CASTGC``
    cookie lets us request a new, unused service ticket from the same session.
    """
    if not cookies:
        return ""
    session = requests.Session()
    session.headers["User-Agent"] = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
    )
    for cookie in cookies:
        name = cookie.get("name")
        value = cookie.get("value")
        if not name or value is None:
            continue
        kwargs = {"path": cookie.get("path") or "/"}
        if cookie.get("domain"):
            kwargs["domain"] = cookie["domain"]
        try:
            session.cookies.set(name, value, **kwargs)
        except (ValueError, TypeError):
            continue
    try:
        response = session.get(cas_url, allow_redirects=False, timeout=30)
    except requests.RequestException:
        return ""
    if response.status_code in (301, 302, 303, 307, 308):
        return ticket_from_url(response.headers.get("Location", "")) or ""
    return ""


def login_via_browser(
    cas_url: str,
    timeout: float = 300.0,
    debug: bool = False,
    service_host: str = "vpn.sdu.edu.cn",
    headless: bool = False,
    username: str | None = None,
    password: str | None = None,
) -> BrowserResult:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # pragma: no cover - depends on optional install
        raise BrowserUnavailable(
            "未安装 playwright。执行：pip install playwright && playwright install chromium"
        ) from exc

    captured: dict[str, str] = {}
    jar: list[dict] = []

    service = parse_qs(urlparse(cas_url).query).get("service", [""])[0]
    if service:
        service_host = urlparse(service).hostname or service_host

    with sync_playwright() as pw:
        try:
            # A CAS 302 to the portal is followed by the network stack, where
            # page.route() cannot stop it.  Point the portal hostname at
            # localhost for this browser only: the redirect then fails before
            # the ticket leaves the machine, while the URL is still observable.
            # A persistent profile keeps the CAS TGT so later runs skip SMS.
            context = pw.chromium.launch_persistent_context(
                user_data_dir=str(config_dir() / "browser"),
                headless=headless,
                locale="zh-CN",
                args=[
                    f"--host-resolver-rules=MAP {service_host} 127.0.0.1",
                    "--disable-features=DnsOverHttps",
                    "--dns-prefetch-disable",
                ],
            )
        except Exception as exc:  # pragma: no cover - environment specific
            raise BrowserUnavailable(f"无法启动 Chromium：{exc}") from exc

        # Chromium may discard session cookies between launches. Persist only
        # this app's CAS cookies explicitly so wake recovery can reuse its TGT.
        cookie_file = config_dir() / "cas_browser_cookies.json"
        if cookie_file.exists():
            try:
                saved = json.loads(cookie_file.read_text("utf-8"))
                context.add_cookies(saved)
            except (OSError, ValueError, TypeError):
                pass
        page = context.pages[0] if context.pages else context.new_page()
        if headless:
            # Keep the same browser identity when switching to background login.
            cdp = context.new_cdp_session(page)
            ua = page.evaluate("navigator.userAgent").replace("HeadlessChrome/", "Chrome/")
            cdp.send("Network.setUserAgentOverride", {"userAgent": ua})

        def remember(url: str) -> None:
            if "ticket=" in url and "/passport/v1/auth/cas" in url:
                captured.setdefault("url", url)

        def intercept(route) -> None:
            url = route.request.url
            if "ticket=" in url and "/passport/v1/auth/cas" in url:
                captured.setdefault("url", url)
                route.abort()
            else:
                route.continue_()

        page.route("**/passport/v1/auth/cas*", intercept)
        page.on("request", lambda req: remember(req.url))
        page.on("requestfailed", lambda req: remember(req.url))
        page.on("framenavigated", lambda frame: remember(frame.url))

        try:
            page.goto(cas_url, wait_until="domcontentloaded", timeout=45_000)
        except Exception:
            pass

        if username and password:
            # Use the real page's own JS for the device fingerprint and
            # /cas/device check.  The synthetic CasClient fingerprint is a
            # different device to CAS and can produce a false "wrong password"
            # page, so unattended logins go through Chromium as well.
            try:
                page.wait_for_selector("#un", timeout=8000)
                page.fill("#un", username)
                page.fill("#pd", password)
                page.click("#index_login_btn")
                if debug:
                    print("[browser] auto-filled CAS credentials")
                page.wait_for_timeout(1200)
                body = page.inner_text("body")
                if "用户名密码错误" in body or "账号或密码错误" in body:
                    raise CasError("学号或密码错误")
            except CasError:
                raise
            except Exception as exc:
                if debug:
                    print(f"[browser] auto-fill skipped: {exc}")

        if headless:
            print("正在后台恢复本程序的 CAS 登录状态。")
        else:
            print("已打开 CAS 登录页。请在弹出的窗口里完成登录（含短信验证码），")
            print("登录成功后由本程序接收学校网关的认证回调并关闭窗口，不启动官方 aTrust 应用。")

        deadline = time.monotonic() + timeout
        try:
            while time.monotonic() < deadline:
                if captured.get("url"):
                    break
                if page.is_closed():
                    break
                page.wait_for_timeout(400)
        except KeyboardInterrupt:
            pass
        finally:
            try:
                # Cookies survive the redirect if the proxy bypassed our block;
                # in that case the browser, not us, owns the logged-in session.
                jar = context.cookies()
                cas_host = urlparse(cas_url).hostname or ""
                retained = [c for c in jar if cas_host == c.get("domain", "").lstrip(".")
                            or cas_host.endswith("." + c.get("domain", "").lstrip("."))]
                if retained:
                    fd, tmp = tempfile.mkstemp(prefix=".cas-", dir=config_dir())
                    try:
                        with os.fdopen(fd, "w") as stream:
                            json.dump(retained, stream)
                        os.replace(tmp, cookie_file)
                    finally:
                        if os.path.exists(tmp): os.unlink(tmp)
                context.close()
            except Exception:
                pass

    url = captured.get("url", "")
    ticket = ticket_from_url(url)
    if not ticket:
        if url:
            raise CasError(f"捕获到的回调里没有 ticket：{url[:200]}")
        raise CasError("浏览器登录未完成或超时，没有捕获到 CAS 回调。")
    if debug:
        print(f"[browser] captured {url.split('?')[0]}, cookies={len(jar)}")
    return BrowserResult(ticket=ticket, cookies=jar)
