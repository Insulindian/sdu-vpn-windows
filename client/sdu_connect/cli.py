"""Command line interface."""

from __future__ import annotations

import argparse
import dataclasses
import getpass
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

import requests
from urllib.parse import parse_qs, urlparse

from . import runner
from .browser import login_via_browser, refresh_service_ticket
from .cas import CasClient, CasError, SecondFactorError, ticket_from_url
from .config import (
    Config,
    client_data_path,
    config_dir,
    config_path,
    device_path,
    ensure_device_identity,
    keychain_get,
    keychain_set,
)
from .fingerprint import DeviceIdentity
from .portal import Portal, PortalError


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", help="配置文件路径（默认 ~/.config/sdu-connect/config.toml）")
    parser.add_argument("--server", help="aTrust 门户域名")
    parser.add_argument("--port", type=int, help="aTrust 门户端口")
    parser.add_argument("--username", help="学号")
    parser.add_argument("--login-domain", help="CAS 登录域（默认从服务端读取）")
    parser.add_argument("--socks-bind", help="SOCKS5 监听地址，默认 127.0.0.1:1080")
    parser.add_argument("--http-bind", help="HTTP 代理监听地址，默认 127.0.0.1:1081")
    parser.add_argument("--zju-connect", help="zju-connect 可执行文件路径")
    parser.add_argument("--debug", action="store_true", default=None, help="打印请求细节")


def _apply(args: argparse.Namespace, cfg: Config) -> Config:
    overrides = {
        "server": args.server,
        "port": args.port,
        "username": args.username,
        "login_domain": args.login_domain,
        "socks_bind": args.socks_bind,
        "http_bind": args.http_bind,
        "zju_connect": args.zju_connect,
        "auth_type": getattr(args, "auth_type", None),
        "phone": getattr(args, "phone", None),
        "debug": args.debug,
    }
    clean = {key: value for key, value in overrides.items() if value is not None}
    return dataclasses.replace(cfg, **clean)


def _resolve_password(args: argparse.Namespace, cfg: Config) -> str:
    if getattr(args, "password", None):
        return args.password
    env = os.environ.get("SDU_PASSWORD")
    if env:
        return env
    if cfg.username:
        stored = keychain_get(cfg.username)
        if stored:
            return stored
    if not sys.stdin.isatty():
        raise SystemExit("需要密码：请用 --password、SDU_PASSWORD 或运行 set-password 写入钥匙串")
    return getpass.getpass(f"{cfg.username} 的密码: ")


def _sms_provider(args: argparse.Namespace):
    fixed = getattr(args, "sms_code", None) or os.environ.get("SDU_SMS_CODE")

    def provider(masked: str) -> str:
        if fixed:
            return fixed
        if not sys.stdin.isatty():
            raise SecondFactorError("需要短信验证码，但当前不是交互终端；请用 --sms-code")
        return input(f"短信验证码已发送至 {masked}，请输入: ")

    return provider


def _load_device(create: bool) -> DeviceIdentity:
    device = DeviceIdentity.load(device_path())
    if device:
        return device
    if not create:
        raise SystemExit("还没有设备指纹，请先运行 up/login")
    device = DeviceIdentity.generate()
    device.save(device_path())
    print(f"已生成设备指纹：{device_path()}")
    return device



@dataclass
class LoginOutcome:
    ticket: str = ""
    domain: str = ""
    used_sms: bool = False
    sid: str = ""
    device_id: str = ""
    resource: str = ""


def _adopt_session(
    portal: Portal, domain: str, ticket: str, browser_cookies: list[dict] | None = None
) -> tuple[str, str, str]:
    """Finish authentication before exporting a session to the tunnel."""
    # Reuse the terminal identity that the official aTrust client already
    # enrolled on this machine; a brand-new ID is rejected by the gateway's
    # trusted-endpoint policy (code 75500503) for web-based logins.
    device_id = ensure_device_identity()
    path = client_data_path()
    try:
        resource = portal.complete_cas(domain, ticket, device_id)
    except (PortalError, requests.RequestException) as exc:
        if isinstance(exc, PortalError):
            raise SystemExit(f"客户端会话认证失败：{exc}") from exc
        raise SystemExit("客户端会话请求失败，请检查网络并重新登录（票据可能已经消费）") from exc

    # Export only cookies applicable to this exact HTTPS resource URL. Store
    # the host including a non-default port, as expected by Go's cookie jar.
    from http.cookies import SimpleCookie
    request = requests.Request("GET", portal.base + "/controller/v1/user/clientResource").prepare()
    raw = requests.cookies.get_cookie_header(portal.session.cookies, request) or ""
    selected = SimpleCookie()
    selected.load(raw)
    sid = selected["sid"].value if "sid" in selected else ""
    if not sid:
        raise SystemExit("认证成功但没有适用于资源接口的 sid cookie；停止导出会话")
    host = urlparse(portal.base).netloc
    cookies = [
        {"host": host, "scheme": "https", "name": key, "value": item.value}
        for key, item in selected.items()
    ]
    data = resource.get("data") or {}
    app_data = ((data.get("appList") or {}).get("data") or {})
    if not (app_data.get("config") or {}).get("nodeGroupConf"):
        raise SystemExit("已登录但 clientResource 没有隧道节点配置；不能启动隧道")
    resource_path = config_dir() / "resource.json"
    _write_private(resource_path, resource)
    _write_private(path, {"cookies": cookies, "device_id": device_id})
    print("客户端认证及资源校验完成，正在交给隧道。")
    return sid, device_id, str(resource_path)


def _write_private(path: Path, data: dict) -> None:
    import tempfile
    path.parent.mkdir(parents=True, exist_ok=True)
    # mkstemp creates the temporary file with mode 0600, before any secret is written.
    fd, name = tempfile.mkstemp(prefix=".session-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def _login(args: argparse.Namespace, cfg: Config) -> LoginOutcome:
    if getattr(args, "callback_url", None):
        ticket = ticket_from_url(args.callback_url)
        if not ticket:
            raise SystemExit("回调 URL 里没有 ticket 参数")
        domain = cfg.login_domain or "pass.sdu.edu.cn"
        if getattr(args, "session", False):
            sid, device_id, resource = _adopt_session(
                Portal(cfg.server, cfg.port, debug=cfg.debug), domain, ticket
            )
            return LoginOutcome(domain=domain, sid=sid, device_id=device_id, resource=resource)
        return LoginOutcome(ticket=ticket, domain=domain)

    portal = Portal(cfg.server, cfg.port, debug=cfg.debug)
    try:
        config = portal.auth_config()
        cas_server = portal.cas_server(config)
        cas_url = portal.cas_login_url(config)
    except (PortalError, OSError, requests.RequestException) as exc:
        raise SystemExit("无法连接 aTrust 门户，请检查网络、TLS 证书及服务端响应") from exc

    domain = cfg.login_domain or cas_server.login_domain

    if getattr(args, "browser", False):
        try:
            browser_result = login_via_browser(
                cas_url,
                timeout=getattr(args, "browser_timeout", 300.0),
                debug=cfg.debug,
                headless=getattr(args, "headless", False),
            )
        except CasError as exc:
            raise SystemExit(f"浏览器登录失败：{exc}") from exc

        # Chromium may already have followed the gateway redirect and spent the
        # captured ticket.  Mint a fresh one from the same CAS session.
        fresh = refresh_service_ticket(cas_url, browser_result.cookies)
        ticket = fresh or browser_result.ticket
        if fresh:
            print("已用浏览器 CAS 会话刷新单次票据。")

        if getattr(args, "session", False):
            sid, device_id, resource = _adopt_session(
                portal, domain, ticket, browser_result.cookies
            )
            return LoginOutcome(domain=domain, sid=sid, device_id=device_id, resource=resource)
        return LoginOutcome(ticket=ticket, domain=domain)

    if not cfg.username:
        raise SystemExit("缺少 --username（或 SDU_USERNAME / 配置文件里的 username）")

    if cfg.debug:
        print(f"[cli] login_domain={domain}")
        print(f"[cli] cas_url={cas_url}")

    password = _resolve_password(args, cfg)
    device = _load_device(create=True)
    client = CasClient(
        cas_url=cas_url,
        username=cfg.username,
        password=password,
        device=device,
        timeout=25.0,
        debug=cfg.debug,
        save_device=not getattr(args, "no_save_device", False),
    )
    try:
        result = client.login(_sms_provider(args))
    except requests.RequestException as exc:
        raise SystemExit("CAS 请求失败，请检查网络并重新登录") from exc
    except CasError as exc:
        raise SystemExit(f"登录失败：{exc}\n如果反复失败，加 --browser 用真实浏览器登录一次。") from exc

    if result.used_sms and not getattr(args, "no_save_device", False):
        print("本次已完成短信认证，设备已授信；下次登录应不再需要短信。")
    if getattr(args, "session", False):
        sid, device_id, resource = _adopt_session(portal, domain, result.ticket)
        return LoginOutcome(
            domain=domain,
            used_sms=result.used_sms,
            sid=sid,
            device_id=device_id,
            resource=resource,
        )
    return LoginOutcome(ticket=result.ticket, domain=domain, used_sms=result.used_sms)


def command_login(args: argparse.Namespace, cfg: Config) -> int:
    outcome = _login(args, cfg)
    if args.json:
        print(
            json.dumps(
                {"ticket": outcome.ticket, "login_domain": outcome.domain, "sid": outcome.sid},
                ensure_ascii=False,
            )
        )
    else:
        print(outcome.ticket or outcome.sid)
    return 0


def command_up(args: argparse.Namespace, cfg: Config) -> int:
    current = runner.status(cfg)
    if current["running"]:
        print(f"已在运行（pid {current['pid']}）。先执行 down。")
        return 1

    if cfg.auth_type != "auth/cas":
        # zju-connect performs these logins itself; no CAS ticket involved.
        domain = cfg.login_domain or "local"
        password = None
        if cfg.auth_type == "auth/psw":
            if not cfg.username:
                raise SystemExit("auth/psw 需要 --username")
            password = _resolve_password(args, cfg)
        elif not cfg.phone:
            raise SystemExit("auth/smsCheckCode 需要 --phone")
        try:
            return runner.run(cfg, domain, password=password, detach=args.detach)
        except runner.RunnerError as exc:
            raise SystemExit(str(exc)) from exc

    outcome = _login(args, cfg)
    try:
        return runner.run(
            cfg,
            outcome.domain,
            outcome.ticket,
            sid=outcome.sid,
            device_id=outcome.device_id,
            resource=outcome.resource,
            detach=args.detach,
        )
    except runner.RunnerError as exc:
        raise SystemExit(str(exc)) from exc


def command_down(args: argparse.Namespace, cfg: Config) -> int:
    print("已停止。" if runner.stop() else "当前没有运行中的实例。")
    return 0


def command_status(args: argparse.Namespace, cfg: Config) -> int:
    info = runner.status(cfg)
    if args.json:
        print(json.dumps(info, ensure_ascii=False))
        return 0 if info["running"] else 1
    if not info["running"]:
        print("未运行")
        return 1
    print(f"运行中  pid {info['pid']}")
    print(f"SOCKS5  {info['socks']}  {'已监听' if info['socks_open'] else '未监听'}")
    print(f"HTTP    {info['http']}  {'已监听' if info['http_open'] else '未监听'}")
    return 0


def command_fingerprint(args: argparse.Namespace, cfg: Config) -> int:
    device = _load_device(create=args.create)
    if args.json:
        print(json.dumps({"details": device.details, "murmur_s": device.murmur_s}, ensure_ascii=False))
    else:
        print(f"目录：{config_dir()}")
        print(f"murmur_s：{device.murmur_s}")
        print("details：")
        print(device.details, end="")
    return 0


def command_new_device(args: argparse.Namespace, cfg: Config) -> int:
    device = DeviceIdentity.generate()
    device.save(device_path())
    print(f"已生成新的设备指纹：{device.murmur_s}")
    print("下次登录需要重新短信验证。")
    return 0


def command_set_password(args: argparse.Namespace, cfg: Config) -> int:
    if os.name == "nt":
        print("Windows 版不保存密码；请使用 --browser 在真实 CAS 页面登录。")
        return 1
    if not cfg.username:
        raise SystemExit("请同时提供 --username")
    password = getpass.getpass(f"{cfg.username} 的密码: ")
    confirm = getpass.getpass("再输一次: ")
    if password != confirm:
        raise SystemExit("两次输入不一致")
    if keychain_set(cfg.username, password):
        print("已写入 macOS 钥匙串。")
        return 0
    print("当前系统不支持钥匙串，请改用 SDU_PASSWORD 环境变量。")
    return 1


def command_auth_info(args: argparse.Namespace, cfg: Config) -> int:
    try:
        return runner.auth_info(cfg)
    except runner.RunnerError as exc:
        raise SystemExit(str(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sdu-connect",
        description="山东大学 aTrust 替代：CAS 自动登录 + 本地 SOCKS5/HTTP 代理",
    )
    _add_common(parser)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("auth-info", help="列出服务端支持的认证方式")
    p.set_defaults(func=command_auth_info)

    p = sub.add_parser("login", help="只做 CAS 登录并输出 ticket")
    p.add_argument("--password")
    p.add_argument("--sms-code")
    p.add_argument("--no-save-device", action="store_true")
    p.add_argument("--callback-url", help="跳过自动登录，直接从浏览器回调 URL 取 ticket")
    p.add_argument("--browser", action="store_true", help="打开真实浏览器完成 CAS 登录")
    p.add_argument("--browser-timeout", type=float, default=300.0, help="浏览器等待秒数")
    p.add_argument("--session", action="store_true", help="完成客户端认证后将会话交给隧道（不跳过终端策略）")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=command_login)

    p = sub.add_parser("up", help="登录并启动代理")
    p.add_argument("--password")
    p.add_argument("--sms-code")
    p.add_argument("--no-save-device", action="store_true")
    p.add_argument("--callback-url")
    p.add_argument("--browser", action="store_true", help="打开真实浏览器完成 CAS 登录")
    p.add_argument("--browser-timeout", type=float, default=300.0)
    p.add_argument("--session", action="store_true", help="完成客户端认证后将会话交给隧道（不跳过终端策略）")
    p.add_argument(
        "--auth-type",
        choices=["auth/cas", "auth/psw", "auth/smsCheckCode"],
        default=None,
        help="认证方式：CAS（默认）/ 本地密码 / 短信",
    )
    p.add_argument("--phone", help="auth/smsCheckCode 用的手机号")
    p.add_argument("-d", "--detach", action="store_true", help="后台运行")
    p.set_defaults(func=command_up)

    p = sub.add_parser("down", help="停止代理")
    p.set_defaults(func=command_down)

    p = sub.add_parser("status", help="查看运行状态")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=command_status)

    p = sub.add_parser("fingerprint", help="查看当前设备指纹")
    p.add_argument("--create", action="store_true", help="不存在时创建")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=command_fingerprint)

    p = sub.add_parser("new-device", help="重置设备指纹（下次需短信）")
    p.set_defaults(func=command_new_device)

    p = sub.add_parser("set-password", help="把密码写入 macOS 钥匙串")
    p.set_defaults(func=command_set_password)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = Config.load(Path(args.config) if args.config else config_path())
    cfg = _apply(args, cfg)
    return int(args.func(args, cfg) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
