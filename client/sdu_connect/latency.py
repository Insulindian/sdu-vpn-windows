"""Latency and SSH authentication checks through the local proxy."""
from __future__ import annotations

import os
import subprocess
import time
from datetime import datetime

import requests
import urllib3

from .sshconfig import parse_hosts

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROXY = "http://127.0.0.1:1081"
CAMPUS_URL = "https://www.sdu.edu.cn/"
PORTAL_URL = "https://sduyjs.sdu.edu.cn/"
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# Hosts listed in SDU_SKIP_SSH (comma separated) keep their ProxyCommand but are
# not probed by the manual speed test.  Nothing is skipped by default, so no
# host names from one particular machine end up in the source.
SKIP_SSH = {
    item.strip().lower()
    for item in os.environ.get("SDU_SKIP_SSH", "").split(",")
    if item.strip()
}


def _https(url: str, timeout: float = 8.0) -> dict:
    started = time.perf_counter()
    try:
        response = requests.get(
            url,
            proxies={"http": PROXY, "https": PROXY},
            timeout=timeout,
            allow_redirects=False,
            verify=False,
        )
        elapsed = int((time.perf_counter() - started) * 1000)
        return {"ok": response.status_code < 500, "ms": elapsed, "status": response.status_code}
    except requests.RequestException as exc:
        return {"ok": False, "ms": None, "error": type(exc).__name__}


def _ssh_auth(alias: str) -> dict:
    """Run a real SSH login check, not just a TCP port probe.

    BatchMode avoids password/passphrase prompts.  The SSH config supplies the
    ProxyCommand, so this exercises the exact path used by VSCode Remote-SSH.
    """
    started = time.perf_counter()
    command = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "StrictHostKeyChecking=accept-new",
        alias,
        "true",
    ]
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=25,
            creationflags=_NO_WINDOW,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "state": "unreachable", "ms": None, "error": "超时"}
    except OSError as exc:
        return {"ok": False, "state": "error", "ms": None, "error": f"无法运行 ssh: {exc}"}

    elapsed = int((time.perf_counter() - started) * 1000)
    stderr = (process.stderr or "").strip()
    lowered = stderr.lower()

    if process.returncode == 0:
        return {"ok": True, "state": "ok", "ms": elapsed, "error": ""}
    if any(
        marker in lowered
        for marker in (
            "permission denied",
            "authentication failed",
            "no supported authentication",
            "incorrect passphrase",
        )
    ):
        return {"ok": True, "state": "auth_failed", "ms": elapsed, "error": "认证失败"}
    if any(
        marker in lowered
        for marker in (
            "timed out",
            "timeout",
            "connection refused",
            "no route",
            "cannot connect",
            "could not resolve",
            "connection closed",
        )
    ):
        return {"ok": False, "state": "unreachable", "ms": None, "error": "不可达"}
    return {
        "ok": False,
        "state": "error",
        "ms": elapsed,
        "error": stderr[:160] or "ssh 失败",
    }


def measure() -> dict:
    result = {
        "checkedAt": datetime.now().isoformat(timespec="seconds"),
        "campus": {"label": "学校主页", **_https(CAMPUS_URL)},
        "portal": {"label": "校内门户", **_https(PORTAL_URL)},
        "ssh": [],
    }
    for host in parse_hosts()[:6]:
        target = host.get("hostname") or host["aliases"][0]
        port = int(host.get("port") or 22)
        for alias in host["aliases"][:2]:
            if alias.lower() in SKIP_SSH:
                continue
            item = {
                "alias": alias,
                "target": f"{target}:{port}",
            }
            item.update(_ssh_auth(alias))
            result["ssh"].append(item)
    return result
