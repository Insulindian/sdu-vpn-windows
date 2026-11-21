"""Modern webview desktop app for the Windows client."""
from __future__ import annotations

import ctypes
import json
import os
import re
import sys
import threading
import time
from pathlib import Path

import webview

from . import runner
from .browser import login_via_browser, refresh_service_ticket
from .cas import CasError, CredentialsError, SecondFactorError
from .cli import _adopt_session
from .config import Config, client_data_path, config_dir
from .credentials import clear_saved, load_saved, save_saved
from .latency import measure
from .portal import Portal
from .session import SessionError, resume_session
from .sshconfig import configure_ssh_proxy, ssh_hosts
from .winproxy import ProxyError, WindowsProxy

APP_ROOT = Path(__file__).resolve().parent.parent.parent
WEBUI = Path(__file__).resolve().parent / "webui" / "index.html"
SSH_PROXY = APP_ROOT / "windows" / "ssh-proxy.cmd"
BROWSER_TIMEOUT = 900
STATE_FILE = config_dir() / "ui-state.json"
LOG_FILE = config_dir() / "windows-app.log"


class Controller:
    def __init__(self) -> None:
        self._config = Config.load()
        self._winproxy = WindowsProxy()
        self._lock = threading.Lock()
        self._busy = False
        self._connected_at: float | None = None
        self._sms_event = threading.Event()
        self._sms_code = ""
        self._sms_waiting = False
        creds = load_saved()
        self._cred_username = creds.get("username", "") if creds else ""
        ui = self._load_ui()
        self._system_proxy = bool(ui.get("systemProxy"))
        if self._system_proxy:
            self._winproxy.restore_stale()
        else:
            # The user keeps Clash as the system proxy; never replay an old
            # PAC snapshot over Clash's settings.
            self._winproxy.discard_stale()
        self._state = {
            "mode": "proxy" if ui.get("mode") == "proxy" else "direct",
            "status": "disconnected",
            "message": "未连接",
            "ip": "",
            "session": "none",
            "testing": False,
            "latency": None,
            "smsPrompt": None,
            "logs": [],
        }

    # ------------------------------------------------------------------ state

    def _load_ui(self) -> dict:
        try:
            data = json.loads(STATE_FILE.read_text("utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _load_mode(self) -> str:
        return "proxy" if self._load_ui().get("mode") == "proxy" else "direct"

    def _save_state(self) -> None:
        try:
            STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            STATE_FILE.write_text(
                json.dumps(
                    {
                        "mode": self._state.get("mode", "direct"),
                        "systemProxy": self._system_proxy,
                    }
                ),
                "utf-8",
            )
        except OSError:
            pass

    def _update(self, **values) -> None:
        with self._lock:
            self._state.update(values)

    def log(self, message: str) -> None:
        line = f"{time.strftime('%H:%M:%S')}  {message}"
        with self._lock:
            logs = self._state.setdefault("logs", [])
            logs.append(line)
            if len(logs) > 200:
                del logs[: len(logs) - 200]
        try:
            LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
            with LOG_FILE.open("a", encoding="utf-8") as handle:
                handle.write(time.strftime("[%Y-%m-%d %H:%M:%S] ") + message + "\n")
        except OSError:
            pass
        print(line, flush=True)

    def get_state(self) -> dict:
        with self._lock:
            state = dict(self._state)
            logs = list(state.get("logs") or [])
        state["logs"] = logs[-140:]
        state["uptime"] = (
            int(time.time() - self._connected_at) if self._connected_at else 0
        )
        state["hasSession"] = client_data_path().exists()
        state["sshHosts"] = ssh_hosts()
        state["proxyActive"] = self._winproxy.active
        state["autoLogin"] = {
            "configured": bool(self._cred_username),
            "username": self._cred_username,
        }
        state["systemProxy"] = self._system_proxy
        return state

    def set_mode(self, mode: str) -> dict:
        if mode not in ("direct", "proxy"):
            return {"ok": False, "error": "unknown mode"}
        if mode == "direct":
            threading.Thread(target=self._direct, daemon=True).start()
        elif not self._busy and self._state.get("status") != "connected":
            threading.Thread(target=self._proxy, kwargs={"auto": False}, daemon=True).start()
        return {"ok": True}

    def test(self) -> dict:
        if self._state.get("status") != "connected":
            self._update(message="请先连接校园 VPN")
            return {"ok": False, "error": "not connected"}
        if self._state.get("testing"):
            return {"ok": True}
        threading.Thread(target=self._test_worker, daemon=True).start()
        return {"ok": True}

    def open_logs(self) -> dict:
        try:
            config_dir().mkdir(parents=True, exist_ok=True)
            os.startfile(str(config_dir()))  # type: ignore[attr-defined]
            return {"ok": True}
        except OSError as exc:
            return {"ok": False, "error": str(exc)}

    def set_system_proxy(self, enabled: bool) -> dict:
        """Opt-in PAC takeover.  Clash stays the system proxy by default."""
        self._system_proxy = bool(enabled)
        self._save_state()
        if self._state.get("status") != "connected":
            if not self._system_proxy:
                self._winproxy.restore()
            return {"ok": True, "pending": True}
        try:
            if self._system_proxy:
                self._winproxy.enable()
                self.log("已接管 Windows 系统代理（PAC 自动分流）。")
            else:
                self._winproxy.restore()
                self.log("已恢复 Clash/原系统代理。")
            return {"ok": True}
        except ProxyError as exc:
            self._system_proxy = False
            self._save_state()
            self._winproxy.restore()
            self.log(f"系统代理设置失败：{exc}")
            return {"ok": False, "error": str(exc)}

    def save_login(self, username: str, password: str) -> dict:
        username = (username or "").strip()
        if not username or not password:
            return {"ok": False, "error": "学号和密码不能为空"}
        try:
            save_saved(username, password)
        except OSError as exc:
            return {"ok": False, "error": f"保存失败：{exc}"}
        self._cred_username = username
        self.log(f"自动登录已配置：{username}")
        return {"ok": True}

    def clear_login(self) -> dict:
        clear_saved()
        self._cred_username = ""
        self.log("已清除保存的自动登录账号。")
        return {"ok": True}

    def submit_sms(self, code: str) -> dict:
        if not self._sms_waiting:
            return {"ok": False, "error": "当前没有等待短信验证码"}
        self._sms_code = (code or "").strip()
        self._update(smsPrompt=None)
        self._sms_event.set()
        return {"ok": True}

    def cancel_sms(self) -> dict:
        if self._sms_waiting:
            self._sms_code = ""
            self._sms_event.set()
        self._update(smsPrompt=None)
        return {"ok": True}

    def auto_start(self) -> None:
        if self._load_mode() == "proxy":
            threading.Thread(target=self._proxy, kwargs={"auto": True}, daemon=True).start()

    def shutdown(self, *args) -> None:
        try:
            runner.stop()
        finally:
            try:
                if self._system_proxy:
                    self._winproxy.restore()
                else:
                    self._winproxy.discard_stale()
            except Exception:
                pass

    # --------------------------------------------------------------- workers

    def _direct(self) -> None:
        with self._lock:
            if self._busy:
                return
            self._busy = True
        self.log("正在切换到直连…")
        try:
            runner.stop()
            if self._system_proxy:
                self._winproxy.restore()
            else:
                self._winproxy.discard_stale()
            self._connected_at = None
            self._update(
                mode="direct",
                status="disconnected",
                message="直连模式：系统代理已恢复",
                ip="",
                session="none",
                latency=None,
            )
            self._save_state()
            self.log("已断开校园 VPN。")
        except Exception as exc:
            self.log(f"切换直连失败：{exc}")
            self._update(status="error", message=f"切换直连失败：{exc}")
        finally:
            with self._lock:
                self._busy = False

    def _proxy(self, auto: bool) -> None:
        with self._lock:
            if self._busy:
                return
            self._busy = True
        self._update(
            mode="proxy",
            status="connecting",
            message="正在恢复上次会话…" if auto else "正在连接校园网络…",
            latency=None,
        )
        try:
            domain = "pass.sdu.edu.cn"
            session_kind = "resumed"
            try:
                sid, device_id, resource = resume_session(self._config)
                self.log("已复用保存的会话，无需重新登录。")
            except SessionError as exc:
                sso = self._sso_login()
                if sso:
                    sid, device_id, resource, domain = sso
                    session_kind = "sso"
                else:
                    creds = load_saved()
                    if creds:
                        self.log(f"保存的会话不可用：{exc}；尝试自动登录…")
                        try:
                            sid, device_id, resource, domain = self._auto_login(creds)
                            session_kind = "auto"
                        except CredentialsError as login_exc:
                            self.log(f"自动登录失败（账号或密码）：{login_exc}")
                            self._update(
                                status="error",
                                message="自动登录失败：学号或密码错误，请在「自动登录设置」中更新",
                            )
                            return
                        except CasError as login_exc:
                            self.log(f"自动登录失败：{login_exc}")
                            if auto:
                                self._update(
                                    status="disconnected",
                                    message=f"自动登录失败：{login_exc}",
                                )
                                return
                            self.log("改用浏览器完成 CAS 登录…")
                            sid, device_id, resource, domain = self._cas_login()
                            session_kind = "cas"
                    else:
                        if auto:
                            self.log(f"保存的会话不可用：{exc}")
                            self._update(
                                status="disconnected",
                                message="上次的会话已过期，点击「代理」重新登录",
                            )
                            return
                        self.log(f"保存的会话不可用：{exc}；正在打开 CAS 登录页…")
                        sid, device_id, resource, domain = self._cas_login()
                        session_kind = "cas"

            self.log("正在启动 zju-connect…")
            runner.stop()
            runner.run(
                self._config,
                domain,
                sid=sid,
                device_id=device_id,
                resource=resource,
                detach=True,
            )
            socks = runner.wait_for_port(self._config.socks_bind, 12)
            http = runner.wait_for_port(self._config.http_bind, 12)
            if not socks or not http:
                raise RuntimeError("zju-connect 已启动，但本地代理端口未监听")

            if self._system_proxy:
                try:
                    self._winproxy.enable()
                    self.log("已接管 Windows 系统代理（PAC 自动分流）。")
                except ProxyError as exc:
                    self.log(f"系统代理设置失败（隧道仍可用）：{exc}")
            else:
                self._winproxy.discard_stale()
                self.log("未接管 Windows 系统代理，Clash 设置保持不变。")

            try:
                hosts = configure_ssh_proxy(str(SSH_PROXY))
                if hosts:
                    self.log("已为 SSH 主机配置代理：" + "、".join(hosts))
            except Exception as exc:
                self.log(f"SSH 代理配置失败：{exc}")

            self._connected_at = time.time()
            ip = self._read_ip()
            self._update(
                mode="proxy",
                status="connected",
                message="已连接校园网络",
                ip=ip or "已连接",
                session=session_kind,
            )
            self._save_state()
            self.log("连接完成。")
        except Exception as exc:
            self.log(f"连接失败：{type(exc).__name__}: {exc}")
            try:
                runner.stop()
                self._winproxy.restore()
            except Exception:
                pass
            self._update(
                mode="proxy",
                status="error",
                message=f"连接失败：{exc}",
                ip="",
                session="none",
            )
        finally:
            with self._lock:
                self._busy = False

    def _sso_login(self) -> tuple[str, str, str, str] | None:
        """Use the trusted Chromium CAS session (CASTGC) for a silent login.

        This is the preferred automatic path: it never asks for a password or
        an SMS code, and it uses the browser fingerprint the school already
        trusts.  It only fails when the CAS session itself has expired.
        """
        cookie_file = config_dir() / "cas_browser_cookies.json"
        if not cookie_file.exists():
            return None
        try:
            cookies = json.loads(cookie_file.read_text("utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(cookies, list) or not cookies:
            return None

        try:
            portal = Portal(self._config.server, self._config.port, debug=True)
            config = portal.auth_config()
            cas = portal.cas_server(config)
            domain = self._config.login_domain or cas.login_domain
            cas_url = portal.cas_login_url(config)
            ticket = refresh_service_ticket(cas_url, cookies)
            if not ticket:
                return None
            self.log("已用浏览器 CAS 会话自动登录（无需密码/验证码）。")
            sid, device_id, resource = _adopt_session(portal, domain, ticket)
            return sid, device_id, resource, domain
        except Exception as exc:
            self.log(f"浏览器 CAS 会话不可用：{exc}")
            return None

    def _auto_login(self, creds: dict) -> tuple[str, str, str, str]:
        portal = Portal(self._config.server, self._config.port, debug=True)
        config = portal.auth_config()
        cas = portal.cas_server(config)
        domain = self._config.login_domain or cas.login_domain
        cas_url = portal.cas_login_url(config)

        self.log(f"正在用浏览器自动登录 CAS（{creds['username']}）…")
        self.log("如出现短信/图形验证码，请在浏览器窗口完成。")
        result = login_via_browser(
            cas_url,
            timeout=BROWSER_TIMEOUT,
            headless=False,
            username=creds["username"],
            password=creds["password"],
        )
        fresh = refresh_service_ticket(cas_url, result.cookies)
        ticket = fresh or result.ticket
        if fresh:
            self.log("已用 CAS 会话刷新单次票据。")
        self.log("CAS 自动登录成功。")
        sid, device_id, resource = _adopt_session(portal, domain, ticket)
        return sid, device_id, resource, domain

    def _sms_provider(self, masked_phone: str) -> str:
        self._sms_code = ""
        self._sms_event.clear()
        self._sms_waiting = True
        self._update(smsPrompt={"phone": masked_phone or "你的手机"})
        self.log(f"CAS 要求短信验证码（{masked_phone or '手机'}），等待输入…")
        try:
            received = self._sms_event.wait(180)
        finally:
            self._sms_waiting = False
            self._update(smsPrompt=None)
        code = (self._sms_code or "").strip()
        if not received or not code:
            raise SecondFactorError("未输入短信验证码")
        return code

    def _cas_login(self) -> tuple[str, str, str, str]:
        portal = Portal(self._config.server, self._config.port, debug=True)
        config = portal.auth_config()
        cas = portal.cas_server(config)
        domain = self._config.login_domain or cas.login_domain
        cas_url = portal.cas_login_url(config)
        self.log("已打开 CAS 登录页，请在 Chromium 窗口完成登录。")
        result = login_via_browser(cas_url, timeout=BROWSER_TIMEOUT, headless=False)
        fresh = refresh_service_ticket(cas_url, result.cookies)
        ticket = fresh or result.ticket
        if fresh:
            self.log("已用 CAS 会话刷新单次票据。")
        sid, device_id, resource = _adopt_session(portal, domain, ticket)
        return sid, device_id, resource, domain

    def _test_worker(self) -> None:
        self._update(testing=True)
        self.log("开始测速…")
        try:
            result = measure()
            self._update(latency=result, testing=False)
            parts = []
            if result["campus"].get("ms") is not None:
                parts.append(f"学校主页 {result['campus']['ms']} ms")
            if result["portal"].get("ms") is not None:
                parts.append(f"校内门户 {result['portal']['ms']} ms")
            self.log("测速完成：" + ("，".join(parts) or "全部失败"))
            ssh = result.get("ssh") or []
            ok = sum(1 for item in ssh if item.get("state") == "ok")
            auth = sum(1 for item in ssh if item.get("state") == "auth_failed")
            down = sum(1 for item in ssh if item.get("state") == "unreachable")
            self.log(f"SSH 检查：{ok} 可登录，{auth} 认证失败，{down} 不可达")
        except Exception as exc:
            self.log(f"测速失败：{exc}")
            self._update(testing=False)
        finally:
            self._update(testing=False)

    def _read_ip(self) -> str:
        path = config_dir() / "zju-connect.log"
        try:
            lines = path.read_text("utf-8", errors="replace").splitlines()[-400:]
        except OSError:
            return ""
        found = ""
        for line in lines:
            match = re.search(r"Received IP:\s*([0-9.]+)", line)
            if match:
                found = match.group(1)
        return found


_MUTEX = None


def _single_instance() -> bool:
    global _MUTEX
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateMutexW.restype = ctypes.c_void_p
        kernel32.CreateMutexW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_bool,
            ctypes.c_wchar_p,
        ]
        _MUTEX = kernel32.CreateMutexW(None, False, "SDU.VPN.Windows")
        return ctypes.get_last_error() != 183  # ERROR_ALREADY_EXISTS
    except Exception:
        return True


def _ensure_streams() -> None:
    """pythonw gives the process no stdout/stderr; send prints to the log file."""
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        if sys.stdout is None:
            sys.stdout = open(LOG_FILE, "a", encoding="utf-8", buffering=1)
        if sys.stderr is None:
            sys.stderr = open(LOG_FILE, "a", encoding="utf-8", buffering=1)
    except OSError:
        pass


def main() -> int:
    if not _single_instance():
        return 0
    _ensure_streams()
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("SDU.VPN.Windows")
    except Exception:
        pass
    controller = Controller()
    controller.log("SDU VPN 已启动")
    window = webview.create_window(
        "SDU VPN",
        url=WEBUI.as_uri(),
        js_api=controller,
        width=1040,
        height=800,
        x=80,
        y=60,
        min_size=(900, 680),
        background_color="#f4f6fb",
    )
    window.events.closed += controller.shutdown

    def set_icon() -> None:
        try:
            from System.Drawing import Icon

            window.native.Icon = Icon(str(APP_ROOT / "windows" / "sdu-vpn.ico"))
        except Exception:
            pass

    threading.Timer(1.2, controller.auto_start).start()
    webview.start(set_icon, debug=False, private_mode=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


