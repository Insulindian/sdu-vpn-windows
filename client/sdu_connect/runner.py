"""Supervises the zju-connect data plane."""

from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

from .config import Config, client_data_path, log_path, pid_path


class RunnerError(RuntimeError):
    pass


def _candidates(cfg: Config) -> list[str]:
    here = Path(__file__).resolve().parent.parent
    exe = "zju-connect.exe" if os.name == "nt" else "zju-connect"
    return [
        cfg.zju_connect,
        os.environ.get("SDU_ZJU_CONNECT", ""),
        str(here / "bin" / exe),
        str(Path.home() / ".local" / "bin" / exe),
        "/usr/local/bin/zju-connect",
        "/opt/homebrew/bin/zju-connect",
        shutil.which("zju-connect") or "",
    ]


def find_binary(cfg: Config) -> str:
    for candidate in _candidates(cfg):
        if candidate and Path(candidate).expanduser().is_file():
            path = str(Path(candidate).expanduser())
            if os.access(path, os.X_OK):
                return path
    exe = "zju-connect.exe" if os.name == "nt" else "zju-connect"
    expected = Path(__file__).resolve().parent.parent / "bin" / exe
    raise RunnerError(
        f"找不到 {exe}。运行 windows\\install.ps1 自动下载，"
        f"或手动放到 {expected}；也可以用 --zju-connect / SDU_ZJU_CONNECT 指定路径。"
    )


def split_bind(bind: str) -> tuple[str, int]:
    host, _, port = bind.rpartition(":")
    return (host or "127.0.0.1"), int(port)


def build_args(
    binary: str,
    cfg: Config,
    domain: str,
    ticket: str | None = None,
    sid: str = "",
    device_id: str = "",
    resource: str = "",
) -> list[str]:
    args = [
        binary,
        "-protocol",
        "atrust",
        "-server",
        cfg.server,
        "-port",
        str(cfg.port),
        "-auth-type",
        cfg.auth_type,
        "-login-domain",
        domain,
        "-socks-bind",
        cfg.socks_bind,
        "-http-bind",
        cfg.http_bind,
        "-client-data-file",
        str(client_data_path()),
    ]
    if sid and device_id and resource:
        # zju-connect's canResume() path: no login loop, no authCheck.
        args += ["-sid", sid, "-device-id", device_id, "-resource-file", resource]
    elif cfg.auth_type == "auth/cas":
        if ticket:
            args += ["-cas-ticket", ticket]
    elif cfg.auth_type == "auth/psw":
        args += ["-username", cfg.username]
    elif cfg.auth_type == "auth/smsCheckCode":
        args += ["-phone", cfg.phone]
    else:
        args += ["-username", cfg.username]
    args += list(cfg.extra_args)
    return args


def wait_for_port(bind: str, timeout: float = 8.0) -> bool:
    host, port = split_bind(bind)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.25)
    return False


def _write_pid(pid: int, cfg: Config) -> None:
    path = pid_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "pid": pid,
                "started": int(time.time()),
                "server": cfg.server,
                "socks": cfg.socks_bind,
                "http": cfg.http_bind,
            },
            indent=2,
        ),
        "utf-8",
    )


def read_pid() -> dict | None:
    path = pid_path()
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return None


def _alive(pid: int) -> bool:
    if os.name == "nt":
        # os.kill(pid, 0) is NOT a no-op on Windows: it calls TerminateProcess.
        # Explicit restype/argtypes keep the 64-bit process handle intact.
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]
        kernel32.GetExitCodeProcess.restype = ctypes.c_bool
        kernel32.GetExitCodeProcess.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ulong),
        ]
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]

        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            ok = kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
            return bool(ok) and code.value == STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def status(cfg: Config) -> dict:
    info = read_pid() or {}
    pid = int(info.get("pid", 0))
    running = bool(pid) and _alive(pid)
    result = {
        "running": running,
        "pid": pid if running else None,
        "socks": cfg.socks_bind,
        "http": cfg.http_bind,
        "socks_open": wait_for_port(cfg.socks_bind, 0.6),
        "http_open": wait_for_port(cfg.http_bind, 0.6),
    }
    if not running and pid_path().exists():
        pid_path().unlink()
    return result


def stop() -> bool:
    info = read_pid()
    if not info:
        if os.name == "nt":
            # A previous crash may have left zju-connect.exe without a pid file.
            result = subprocess.run(
                ["taskkill", "/IM", "zju-connect.exe", "/T", "/F"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                pid_path().unlink(missing_ok=True)
                return True
        return False
    pid = int(info.get("pid", 0))
    if not pid or not _alive(pid):
        pid_path().unlink(missing_ok=True)
        return False

    if os.name == "nt":
        # /T also stops the tunnel child processes zju-connect may create.
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            capture_output=True,
            timeout=15,
        )
        pid_path().unlink(missing_ok=True)
        return True

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pid_path().unlink(missing_ok=True)
        return False
    for _ in range(40):
        if not _alive(pid):
            break
        time.sleep(0.1)
    else:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    pid_path().unlink(missing_ok=True)
    return True


def run(
    cfg: Config,
    domain: str,
    ticket: str = "",
    password: str | None = None,
    sid: str = "",
    device_id: str = "",
    resource: str = "",
    detach: bool = False,
) -> int:
    binary = find_binary(cfg)
    client_data_path().parent.mkdir(parents=True, exist_ok=True)
    args = build_args(binary, cfg, domain, ticket, sid, device_id, resource)
    child_env = dict(os.environ)
    if password:
        child_env["ZJU_CONNECT_PASSWORD"] = password

    if detach:
        log_path().parent.mkdir(parents=True, exist_ok=True)
        log_fd = os.open(log_path(), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.chmod(log_path(), 0o600)
        log = os.fdopen(log_fd, "ab", buffering=0)
        popen_extra = {}
        if os.name == "nt":
            popen_extra["creationflags"] = (
                subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
            )
        else:
            popen_extra["start_new_session"] = True
        process = subprocess.Popen(
            args,
            stdout=log,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=child_env,
            **popen_extra,
        )
        _write_pid(process.pid, cfg)
        ready = wait_for_port(cfg.socks_bind, 8.0)
        time.sleep(0.5)
        if process.poll() is not None:
            pid_path().unlink(missing_ok=True)
            raise RunnerError(f"zju-connect 启动后立即退出；请在本机检查私有日志：{log_path()}")
        print(f"已后台启动 zju-connect (pid {process.pid})，日志：{log_path()}")
        if not ready:
            print("警告：SOCKS 端口暂未监听，请查看日志确认登录是否成功。")
        return 0

    print(f"启动：{' '.join(args[:6])} …")
    process = subprocess.Popen(args, env=child_env)
    _write_pid(process.pid, cfg)

    def _forward(signum, _frame):
        if process.poll() is None:
            process.send_signal(signum)

    old_int = signal.signal(signal.SIGINT, _forward)
    old_term = signal.signal(signal.SIGTERM, _forward)
    try:
        if wait_for_port(cfg.socks_bind, 8.0):
            print(f"SOCKS5  {cfg.socks_bind}")
            print(f"HTTP    {cfg.http_bind}")
            print("按 Ctrl-C 断开。")
        code = process.wait()
    finally:
        signal.signal(signal.SIGINT, old_int)
        signal.signal(signal.SIGTERM, old_term)
        pid_path().unlink(missing_ok=True)
    return code


def auth_info(cfg: Config) -> int:
    binary = find_binary(cfg)
    args = [
        binary,
        "-protocol",
        "atrust",
        "-server",
        cfg.server,
        "-port",
        str(cfg.port),
        "-auth-info",
    ]
    return subprocess.call(args)
