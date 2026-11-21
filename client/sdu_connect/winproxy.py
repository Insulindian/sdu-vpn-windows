"""Windows per-user proxy configuration for the campus-proxy mode.

The macOS client uses ``networksetup`` to install a PAC URL.  The Windows
equivalent is the WinINET AutoConfigURL under HKCU, which Edge/Chrome and most
desktop applications honour.  The original values are backed up before the
first change and restored on disconnect/exit (and at startup, in case a previous
run crashed).
"""
from __future__ import annotations

import ctypes
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .config import config_dir

PAC_PORT = 18769
_SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
_BACKUP_NAME = "proxy-original.json"
_PROXY_FIELDS = ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL")


class ProxyError(RuntimeError):
    pass


class _PacHandler(BaseHTTPRequestHandler):
    pac = "function FindProxyForURL(url, host) { return 'DIRECT'; }"

    def do_GET(self):  # noqa: N802 - http.server API
        if self.path != "/proxy.pac":
            self.send_error(404)
            return
        data = self.pac.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):  # silence the default stderr logging
        pass


class WindowsProxy:
    def __init__(self) -> None:
        self.backup_path = config_dir() / _BACKUP_NAME
        self.active = False
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._saved: dict | None = None

    # ---------------------------------------------------------------- registry

    @staticmethod
    def _read() -> dict:
        import winreg

        values: dict = {}
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _SETTINGS_KEY) as key:
                for name in _PROXY_FIELDS:
                    try:
                        values[name] = winreg.QueryValueEx(key, name)[0]
                    except OSError:
                        values[name] = None
        except OSError:
            pass
        return values

    @staticmethod
    def _write(values: dict) -> None:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, _SETTINGS_KEY, 0, winreg.KEY_SET_VALUE
        ) as key:
            for name, value in values.items():
                if value is None:
                    try:
                        winreg.DeleteValue(key, name)
                    except OSError:
                        pass
                else:
                    kind = winreg.REG_SZ if isinstance(value, str) else winreg.REG_DWORD
                    winreg.SetValueEx(key, name, 0, kind, value)
        WindowsProxy._notify()

    @staticmethod
    def _notify() -> None:
        try:
            wininet = ctypes.windll.wininet
            wininet.InternetSetOptionW(0, 39, 0, 0)  # SETTINGS_CHANGED
            wininet.InternetSetOptionW(0, 37, 0, 0)  # REFRESH
        except Exception:
            pass

    # -------------------------------------------------------------------- PAC

    def _start_pac(self, pac: str) -> None:
        _PacHandler.pac = pac
        if self._server is not None:
            return
        self._server = ThreadingHTTPServer(("127.0.0.1", PAC_PORT), _PacHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def _stop_pac(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            finally:
                self._server = None
                self._thread = None

    def build_pac(self) -> str:
        fallback = "DIRECT"
        saved = self._saved or {}
        if saved.get("ProxyEnable") and saved.get("ProxyServer"):
            server = str(saved["ProxyServer"]).split(";")[0]
            if "=" in server:  # e.g. "http=host:port;https=host:port"
                server = server.split("=", 1)[1]
            if ":" in server:
                fallback = "PROXY " + server

        return (
            "function FindProxyForURL(url, host) {\n"
            '  if (isPlainHostName(host) || host === "127.0.0.1" || host === "localhost" || host === "vpn.sdu.edu.cn") return "DIRECT";\n'
            '  if (host === "sdu.edu.cn" || dnsDomainIs(host, ".sdu.edu.cn") ||\n'
            '      isInNet(host, "10.0.0.0", "255.0.0.0") ||\n'
            '      isInNet(host, "172.16.0.0", "255.240.0.0") ||\n'
            '      isInNet(host, "192.168.0.0", "255.255.0.0")) return "PROXY 127.0.0.1:1081";\n'
            f'  return "{fallback}";\n'
            "}\n"
        )

    # --------------------------------------------------------------- lifecycle

    def _is_our_pac(self) -> bool:
        try:
            current = self._read()
            return str(current.get("AutoConfigURL") or "") == (
                f"http://127.0.0.1:{PAC_PORT}/proxy.pac"
            )
        except Exception:
            return False

    def discard_stale(self) -> None:
        """Drop a stale backup without touching Clash/another proxy manager."""
        self.backup_path.unlink(missing_ok=True)

    def restore_stale(self) -> None:
        """Restore a backup left behind by a crash, before doing anything else.

        Only touch the registry when the PAC currently in place is ours.  If
        Clash (or another proxy manager) has changed the system proxy since,
        its settings must win.
        """
        if not self.backup_path.exists():
            return
        try:
            saved = json.loads(self.backup_path.read_text("utf-8"))
            if self._is_our_pac():
                self._write(saved)
        except (OSError, ValueError, TypeError):
            pass
        finally:
            self.backup_path.unlink(missing_ok=True)

    def enable(self) -> None:
        if self.active:
            return
        self._saved = self._read()
        try:
            self.backup_path.parent.mkdir(parents=True, exist_ok=True)
            self.backup_path.write_text(
                json.dumps(self._saved, ensure_ascii=False, indent=2), "utf-8"
            )
            self._start_pac(self.build_pac())
            self._write(
                {
                    "AutoConfigURL": f"http://127.0.0.1:{PAC_PORT}/proxy.pac",
                    "ProxyEnable": 0,
                }
            )
            self.active = True
        except Exception as exc:
            self.restore()
            raise ProxyError(f"设置 Windows 系统代理失败：{exc}") from exc

    def restore(self) -> None:
        if self._saved is None and self.backup_path.exists():
            try:
                self._saved = json.loads(self.backup_path.read_text("utf-8"))
            except (OSError, ValueError):
                self._saved = None
        try:
            # If Clash changed the system proxy while we were connected, do
            # not overwrite its newer choice with our pre-connection snapshot.
            if self._saved and self._is_our_pac():
                self._write(self._saved)
        finally:
            self.backup_path.unlink(missing_ok=True)
            self._stop_pac()
            self.active = False
