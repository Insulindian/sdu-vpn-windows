"""Automates the SDU CAS login and returns the aTrust portal ticket.

The login page (``/cas/comm/sdu/js/login.js``) does not POST the password
directly.  It first posts credential hashes plus a browser fingerprint to
``/cas/device`` (``m=1``) to ask "is this a trusted device?":

* ``pass`` / ``binded`` -> continue straight to the form submit
* ``bind``             -> server sent an SMS code, we must post it back (``m=3``)
* ``validErr``         -> wrong username or password

Only then is ``/cas/login`` submitted with ``rsa = strEnc(user + pass + lt)``.
CAS finally redirects to
``https://vpn.sdu.edu.cn:443/passport/v1/auth/cas?ticket=ST-...`` and that
single-use ticket is what the tunnel authenticates with.

SDU's ``/cas/device`` is not always cooperative (it answers 500 for accounts it
cannot resolve, and has been observed failing generally), so the device check is
best-effort: if it fails we reload the form and submit it directly, which is
enough for the password-only path.
"""

from __future__ import annotations

import html
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import parse_qs, urljoin, urlparse

import requests

from .des import str_enc
from .fingerprint import DeviceIdentity

_INPUT = re.compile(r"<input\b[^>]*>", re.I)
_FORM_BLOCK = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
_ATTR = re.compile(r"""([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))""")

SmsProvider = Callable[[str], str]


class CasError(RuntimeError):
    pass


class CredentialsError(CasError):
    pass


class SecondFactorError(CasError):
    pass


@dataclass
class CasLogin:
    ticket: str
    service: str
    used_sms: bool


def _attrs(tag: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for match in _ATTR.finditer(tag):
        key = match.group(1).lower()
        value = match.group(2) or match.group(3) or match.group(4) or ""
        result[key] = html.unescape(value)
    return result


def _parse_login_form(page: str) -> tuple[str, dict[str, str]]:
    """Only look inside the credential form.

    The page also embeds the phone-login and QR templates, which contain inputs
    with names like ``code``; picking those up makes CAS reject the submit.
    """
    form_attrs: dict[str, str] = {}
    form_body = ""
    for attrs_text, body in _FORM_BLOCK.findall(page):
        attrs = _attrs(attrs_text)
        if "lt" in body or "/cas/login" in attrs.get("action", ""):
            form_attrs = attrs
            form_body = body
            break

    if not form_body:
        raise CasError("CAS 页面里找不到登录表单")

    form_action = form_attrs.get("action") or "/cas/login"
    fields: dict[str, str] = {}
    for tag in _INPUT.findall(form_body):
        attrs = _attrs(tag)
        name = attrs.get("name")
        if name:
            fields[name] = attrs.get("value", "")
    return form_action, fields


def ticket_from_url(url: str) -> str | None:
    query = parse_qs(urlparse(url).query)
    values = query.get("ticket")
    return values[0] if values else None


class CasClient:
    def __init__(
        self,
        *,
        cas_url: str,
        username: str,
        password: str,
        device: DeviceIdentity,
        session: requests.Session | None = None,
        timeout: float = 20.0,
        debug: bool = False,
        save_device: bool = True,
        skip_device: bool = False,
    ) -> None:
        self.cas_url = cas_url
        self.username = username
        self.password = password
        self.device = device
        self.session = session or requests.Session()
        self.timeout = timeout
        self.debug = debug
        self.save_device = save_device
        # The /cas/device check is best-effort.  For unattended logins it can
        # report "bind" even when the password form is accepted directly, so
        # callers may skip it and only fall back to the browser if the form
        # submit does not yield a ticket.
        self.skip_device = skip_device
        self.service = parse_qs(urlparse(cas_url).query).get("service", [""])[0]

    def _log(self, message: str) -> None:
        if self.debug:
            print(f"[cas] {message}")

    # ------------------------------------------------------------------ form

    def _load_form(self) -> tuple[str, dict[str, str], str]:
        self._log(f"GET {self.cas_url}")
        page = self.session.get(self.cas_url, timeout=self.timeout)
        page.raise_for_status()
        action, fields = _parse_login_form(page.text)
        if "lt" not in fields or "execution" not in fields:
            raise CasError(
                "CAS 登录页结构已变化（找不到 lt/execution），"
                "请用 --callback-url 手动模式，或更新本项目。"
            )
        login_ticket = fields["lt"]
        fields.update(
            {
                "ul": str(len(self.username)),
                "pl": str(len(self.password)),
                "rsa": str_enc(self.username + self.password + login_ticket),
                "_eventId": fields.get("_eventId", "submit"),
            }
        )
        return action, fields, page.url

    # ---------------------------------------------------------------- device

    def _post_device(self, payload: dict[str, str], referer: str) -> dict[str, str]:
        # jQuery appends sf_request_type=ajax and asks for JSON.
        url = urljoin(self.cas_url, "device") + "?sf_request_type=ajax"
        response = self.session.post(
            url,
            data=payload,
            headers={
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "X-Requested-With": "XMLHttpRequest",
                "Referer": referer,
                "Origin": f"{urlparse(self.cas_url).scheme}://{urlparse(self.cas_url).netloc}",
            },
            timeout=self.timeout,
        )
        self._log(f"POST {url} (m={payload.get('m')}) -> {response.status_code}")
        if response.status_code >= 400:
            raise CasError(f"/cas/device 返回 HTTP {response.status_code}")
        try:
            return response.json()
        except json.JSONDecodeError as exc:
            raise CasError(f"/cas/device 返回的不是 JSON: {response.text[:200]}") from exc

    # ----------------------------------------------------------------- login

    def login(self, sms_provider: SmsProvider) -> CasLogin:
        action, fields, current_url = self._load_form()

        info = ""
        masked_phone = ""
        used_sms = False
        device_error: CasError | None = None
        check: dict[str, str] = {}

        if self.skip_device:
            # Unattended login: the device check can answer "bind" even when
            # the password form is accepted directly.  Try the form first;
            # the caller falls back to the browser if it needs SMS/captcha.
            self._log("skip /cas/device; submitting credentials directly")
        else:
            try:
                check = self._post_device(
                    self.device.as_payload_m1(self.username, self.password), current_url
                )
                info = check.get("info", "")
                masked_phone = str(check.get("m", ""))
            except CasError as exc:
                # Best effort.  Reload so the submit uses a fresh lt/execution.
                device_error = exc
                self._log(f"device check unavailable: {exc}")
                action, fields, current_url = self._load_form()

            if info in ("validErr", "notFound"):
                raise CredentialsError("学号或密码错误（CAS 返回 validErr/notFound）")
            if info == "mobileErr":
                raise SecondFactorError("该账号未绑定手机号，无法完成短信二次认证")

            if info == "bind":
                used_sms = True
                if not masked_phone:
                    masked_phone = "你的手机"
                code = sms_provider(masked_phone).strip()
                if not code:
                    raise SecondFactorError("没有输入短信验证码")

                verify = self._post_device(
                    self.device.as_payload_m3(self.username, code, self.save_device),
                    current_url,
                )
                result = verify.get("info", "")
                if result in ("ok", "most"):
                    if result == "most":
                        print("提示：授信设备已达上限，CAS 已自动移除最早的一台。")
                elif result == "codeErr":
                    raise SecondFactorError("短信验证码错误")
                elif result == "timeout":
                    raise SecondFactorError("短信验证码已过期，请重试")
                elif result == "moreErr":
                    raise SecondFactorError("验证码错误次数过多，请稍后再试")
                else:
                    raise SecondFactorError(f"短信二次认证失败：{result or verify}")
            elif info in ("pass", "binded"):
                self._log("设备已授信，跳过短信")
            elif info:
                raise CasError(f"设备校验返回未知结果：{info or check}")
            else:
                self._log("跳过设备校验，直接提交登录表单")

        submit_url = urljoin(current_url, action)
        self._log(f"POST {submit_url}")
        response = self.session.post(
            submit_url,
            data=fields,
            headers={"Referer": current_url},
            timeout=self.timeout,
            allow_redirects=False,
        )

        ticket, final = self._follow_to_ticket(response)
        if ticket:
            return CasLogin(ticket=ticket, service=self.service, used_sms=used_sms)

        text = final.text if final is not None else ""
        if "用户名密码错误" in text:
            raise CredentialsError("学号或密码错误")

        snippet = re.sub(r"\s+", " ", text)[:300]
        hint = ""
        if device_error:
            hint = f"（设备校验：{device_error}）请用 --callback-url 手动登录一次。"
        raise CasError(f"登录后未拿到 ticket（HTTP {response.status_code}）：{snippet}{hint}")

    def _follow_to_ticket(
        self, response: requests.Response
    ) -> tuple[str | None, requests.Response]:
        for _ in range(10):
            if response.status_code not in (301, 302, 303, 307, 308):
                return ticket_from_url(response.url), response

            location = response.headers.get("Location", "")
            if not location:
                return None, response

            location = urljoin(response.url, location)
            ticket = ticket_from_url(location)
            if ticket:
                # Do not follow: the ticket is single-use and zju-connect must spend it.
                self._log(f"got ticket from {location.split('?')[0]}")
                return ticket, response

            self._log(f"follow {location}")
            response = self.session.get(
                location, timeout=self.timeout, allow_redirects=False
            )
        return None, response
