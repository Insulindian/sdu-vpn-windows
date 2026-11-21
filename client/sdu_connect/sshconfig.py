"""Configure SSH to follow the campus proxy while the VPN is connected.

Windows OpenSSH does not use the system PAC, so each configured SSH host gets a
``ProxyCommand`` that tunnels through the local HTTP proxy.  The helper script
falls back to a direct TCP connection when the proxy is not running, which makes
"直连" mode work without rewriting the SSH config again.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

INCLUDE_LINE = "Include ~/.ssh/sdu-vpn.conf"
MANAGED_NAME = "sdu-vpn.conf"


def _ssh_dir() -> Path:
    return Path.home() / ".ssh"


def parse_hosts() -> list[dict]:
    path = _ssh_dir() / "config"
    if not path.exists():
        return []

    hosts: list[dict] = []
    current: dict | None = None
    for line in path.read_text("utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = re.match(r"(?i)^Host\s+(.+)$", stripped)
        if match:
            aliases = [
                item
                for item in match.group(1).split()
                if item not in ("*", "?") and not item.startswith("!")
            ]
            current = {
                "aliases": aliases,
                "hostname": "",
                "port": 22,
                "has_address": False,
            }
            if aliases:
                hosts.append(current)
            continue
        if current is None:
            continue
        match = re.match(r"(?i)^HostName\s+(.+)$", stripped)
        if match:
            current["hostname"] = match.group(1).strip()
            current["has_address"] = True
            continue
        match = re.match(r"(?i)^Port\s+(\d+)$", stripped)
        if match:
            current["port"] = int(match.group(1))
            current["has_address"] = True

    # A multi-alias block without HostName/Port is an option block (for
    # example the keep-alive block before the Include), not a host definition.
    hosts = [h for h in hosts if h["has_address"] or len(h["aliases"]) == 1]

    # De-duplicate aliases while preserving order.
    seen: set[str] = set()
    unique: list[dict] = []
    for host in hosts:
        aliases = [a for a in host["aliases"] if a not in seen]
        if not aliases:
            continue
        seen.update(aliases)
        unique.append({**host, "aliases": aliases})
    return unique


def ssh_hosts() -> list[str]:
    return [alias for host in parse_hosts() for alias in host["aliases"]]


def configure_ssh_proxy(proxy_command: str) -> list[str]:
    """Write the managed include and make sure it is loaded from ~/.ssh/config."""
    ssh_dir = _ssh_dir()
    ssh_dir.mkdir(parents=True, exist_ok=True)
    hosts = parse_hosts()

    lines = [
        "# Managed by SDU VPN (Windows). Regenerated on every proxy connection.",
        "# The helper falls back to a direct connection when the VPN is off.",
    ]
    if hosts:
        aliases = " ".join(alias for host in hosts for alias in host["aliases"])
        command = proxy_command.replace("\\", "/")
        lines += [
            f"Host {aliases}",
            f'  ProxyCommand "{command}" %h %p',
            # The HTTP fallback drops idle CONNECT tunnels after ~3.5 s, so
            # keep the SSH transport warm even though SOCKS5 is preferred.
            "  ServerAliveInterval 2",
            "  ServerAliveCountMax 3",
        ]
    else:
        lines.append("# No concrete Host entries were found in ~/.ssh/config.")

    (ssh_dir / MANAGED_NAME).write_text("\n".join(lines) + "\n", "utf-8")

    config = ssh_dir / "config"
    existing = config.read_text("utf-8", errors="replace") if config.exists() else ""
    if INCLUDE_LINE not in existing:
        backup = ssh_dir / "config.sdu-vpn.bak"
        if existing and not backup.exists():
            backup.write_text(existing, "utf-8")
        config.write_text(INCLUDE_LINE + "\n\n" + existing, "utf-8")

    return [alias for host in hosts for alias in host["aliases"]]


def remove_ssh_proxy() -> None:
    """Undo configure_ssh_proxy (used by an explicit cleanup action)."""
    ssh_dir = _ssh_dir()
    config = ssh_dir / "config"
    if config.exists():
        content = config.read_text("utf-8", errors="replace")
        content = content.replace(INCLUDE_LINE + "\n\n", "").replace(INCLUDE_LINE + "\n", "")
        config.write_text(content, "utf-8")
    (ssh_dir / MANAGED_NAME).unlink(missing_ok=True)
