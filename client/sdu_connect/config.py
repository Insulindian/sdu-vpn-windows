"""Configuration and local state locations."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tomllib
import uuid
from dataclasses import dataclass, field, fields
from pathlib import Path

APP = "sdu-connect"
KEYCHAIN_SERVICE = "sdu-connect"


def config_dir() -> Path:
    override = os.environ.get("SDU_CONNECT_HOME")
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        # Keep per-user state out of the source tree, next to other Windows
        # application data (Roaming is fine: it is small JSON, no caches).
        base = os.environ.get("APPDATA") or str(Path.home())
        return Path(base) / APP
    return Path.home() / ".config" / APP


def device_path() -> Path:
    return config_dir() / "device.json"


def client_data_path() -> Path:
    return config_dir() / "client_data.json"


def pid_path() -> Path:
    return config_dir() / "run.json"


def log_path() -> Path:
    return config_dir() / "zju-connect.log"


def config_path() -> Path:
    return config_dir() / "config.toml"


@dataclass
class Config:
    server: str = "vpn.sdu.edu.cn"
    port: int = 443
    username: str = ""
    login_domain: str = ""
    socks_bind: str = "127.0.0.1:1080"
    http_bind: str = "127.0.0.1:1081"
    zju_connect: str = ""
    auth_type: str = "auth/cas"
    phone: str = ""
    debug: bool = False
    extra_args: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path | None = None) -> "Config":
        config = cls()
        path = path or config_path()

        if path.exists():
            with path.open("rb") as handle:
                data = tomllib.load(handle)
            allowed = {item.name for item in fields(cls)}
            for key, value in data.items():
                if key in allowed:
                    setattr(config, key, value)

        env_map = {
            "SDU_SERVER": ("server", str),
            "SDU_PORT": ("port", int),
            "SDU_USERNAME": ("username", str),
            "SDU_LOGIN_DOMAIN": ("login_domain", str),
            "SDU_SOCKS_BIND": ("socks_bind", str),
            "SDU_HTTP_BIND": ("http_bind", str),
            "SDU_ZJU_CONNECT": ("zju_connect", str),
            "SDU_AUTH_TYPE": ("auth_type", str),
            "SDU_PHONE": ("phone", str),
            "SDU_DEBUG": ("debug", lambda v: v not in ("", "0", "false", "False")),
        }
        for env_key, (attr, cast) in env_map.items():
            raw = os.environ.get(env_key)
            if raw is not None and raw != "":
                setattr(config, attr, cast(raw))

        return config


def official_device_id() -> str:
    """Return the terminal ID of the installed official aTrust client.

    The gateway only lets an already-trusted terminal skip
    ``auth/bindAuthDevice``; adding a new trusted endpoint from a web login is
    rejected with code 75500503.  The native client stores its terminal ID as a
    32-character uppercase hex string in this small config blob, which is
    enough to reuse the same trusted endpoint for zju-connect.
    """
    if sys.platform != "win32":
        return ""
    appdata = os.environ.get("APPDATA")
    if not appdata:
        return ""
    candidates = [
        Path(appdata) / "Sangfor" / "aTrust" / "database" / "aTrustAuth" / "AppConfig",
        Path(appdata) / "Sangfor" / "aTrust" / "database" / "sdpSec" / "SdpcPubkeyPersistence",
    ]
    for path in candidates:
        try:
            data = path.read_bytes()
        except OSError:
            continue
        match = re.search(rb"(?<![0-9A-Fa-f])[0-9A-F]{32}(?![0-9A-Fa-f])", data)
        if match:
            return match.group(0).decode("ascii")
    return ""


def ensure_device_identity() -> str:
    """Persist the trusted terminal ID, or create one if the client is absent."""
    path = config_dir() / "endpoint_identity.json"
    official = official_device_id()
    if official:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"device_id": official}), "utf-8")
        return official

    if path.exists():
        try:
            existing = json.loads(path.read_text("utf-8")).get("device_id", "")
        except (OSError, ValueError, AttributeError):
            existing = ""
        if isinstance(existing, str) and re.fullmatch(r"[0-9a-fA-F]{32}", existing):
            return existing

    generated = uuid.uuid4().hex
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"device_id": generated}), "utf-8")
    return generated


def keychain_get(account: str) -> str | None:
    if sys.platform != "darwin":
        return None
    try:
        result = subprocess.run(
            ["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account, "-w"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def keychain_set(account: str, password: str) -> bool:
    if sys.platform != "darwin":
        return False
    subprocess.run(
        ["security", "delete-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account],
        capture_output=True,
        check=False,
    )
    result = subprocess.run(
        [
            "security",
            "add-generic-password",
            "-U",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            account,
            "-w",
            password,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0
