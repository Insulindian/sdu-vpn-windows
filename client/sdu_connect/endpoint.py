"""Independent endpoint facts; no official application or SDK calls.

The native client's ``device.type`` is the machine model.  A browser
placeholder cannot represent the endpoint during device enrollment, so only
measured facts are returned and unsupported security checks are never reported
as passing.

macOS uses ``hw.model`` / ``sw_vers``; Windows reads the BIOS strings from the
registry and the version facts from :mod:`platform`.
"""
from __future__ import annotations

import platform
import socket
import subprocess
from collections.abc import Iterable


class EndpointError(RuntimeError):
    pass


def _read(argv: list[str]) -> str:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=5)
    except (OSError, subprocess.SubprocessError) as exc:
        raise EndpointError(f"无法读取本机环境：{argv[0]} {argv[-1]}") from exc
    value = result.stdout.strip()
    if not value:
        raise EndpointError(f"本机环境字段为空：{argv[-1]}")
    return value


def _macos_facts() -> dict[str, str]:
    model = _read(["/usr/sbin/sysctl", "-n", "hw.model"])
    version = _read(["/usr/bin/sw_vers", "-productVersion"])
    arch = platform.machine()
    return {
        "model": model,
        "brand": "Apple",
        "family": "macOS",
        "version": version,
        "arch": arch,
    }


def _windows_facts() -> dict[str, str]:
    """Read the model/manufacturer the same way Windows reports the device.

    ``winreg`` is stdlib and avoids spawning PowerShell/WMI for every login.
    If a value is absent we return a neutral placeholder instead of pretending
    the machine is something it is not.
    """
    model = "PC"
    brand = "PC"
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"HARDWARE\DESCRIPTION\System\BIOS",
        ) as key:
            try:
                model = str(winreg.QueryValueEx(key, "SystemProductName")[0]).strip() or model
            except OSError:
                pass
            try:
                brand = str(winreg.QueryValueEx(key, "SystemManufacturer")[0]).strip() or brand
            except OSError:
                pass
    except (ImportError, OSError):
        pass

    return {
        "model": model,
        "brand": brand,
        "family": "Windows",
        "version": platform.version() or platform.release(),
        "arch": platform.machine() or "x86_64",
    }


def collect_endpoint(device_id: str, requested: Iterable[dict] = ()) -> dict:
    system = platform.system()
    if system == "Darwin":
        facts = _macos_facts()
    elif system == "Windows":
        facts = _windows_facts()
    else:
        raise EndpointError("本次原生终端报告仅实现 macOS 与 Windows；未对其他系统假设终端类型")

    endpoint = {
        "device_id": device_id,
        "device": {"type": facts["model"]},
        "os": {
            "family": facts["family"],
            "version": facts["version"],
            "arch": facts["arch"],
        },
    }
    if system == "Windows":
        # Windows clients report the OEM brand alongside the model.
        endpoint["device"]["brand"] = facts["brand"]

    known = {
        "endpoint.device_id": device_id,
        "endpoint.device.type": facts["model"],
        "endpoint.device_model": facts["model"],
        "endpoint.device_brand": facts["brand"],
        "endpoint.os.hostname": socket.gethostname(),
        "endpoint.os.family": facts["family"],
        "endpoint.os.version": facts["version"],
        "endpoint.os.arch": facts["arch"],
    }

    for item in requested:
        if not isinstance(item, dict):
            raise EndpointError("endpointStrategy.env 中的条目不是对象")
        name = item.get("name", "")
        if item.get("type", "var") != "var" or name not in known:
            # Do not fabricate antivirus/firewall/compliance results.
            raise EndpointError(f"学校要求尚未实现的终端检查项：{name or '(未命名)'}")
        target = endpoint
        parts = name.split(".")[1:]
        for part in parts[:-1]:
            target = target.setdefault(part, {})
        target[parts[-1]] = known[name]
    return endpoint
