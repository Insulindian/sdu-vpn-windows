"""Resume an aTrust session saved by a previous run.

zju-connect and this client both persist ``client_data.json`` (cookies +
trusted terminal ID) and ``resource.json``.  When the gateway session is still
valid we can reconnect without opening the CAS browser at all.
"""
from __future__ import annotations

import json
from pathlib import Path

from .config import Config, client_data_path, config_dir
from .portal import Portal, PortalError

RESOURCE_REQUEST = {
    "resourceType": {
        "sdpPolicy": {},
        "appList": {},
        "favoriteAppList": {},
        "featureCenter": {},
        "uemSpace": {"params": {"action": "login"}},
    }
}


class SessionError(RuntimeError):
    pass


def _cookies_for(portal: Portal, server: str) -> list[dict]:
    cookies = []
    for cookie in portal.session.cookies:
        domain = (cookie.domain or "").lstrip(".")
        if server != domain and not server.endswith("." + domain):
            continue
        cookies.append(
            {
                "host": cookie.domain,
                "scheme": "https",
                "name": cookie.name,
                "value": cookie.value,
            }
        )
    return cookies


def resume_session(cfg: Config) -> tuple[str, str, str]:
    """Return ``(sid, device_id, resource_path)`` for a still-valid session."""
    data_path = client_data_path()
    resource_path = config_dir() / "resource.json"
    if not data_path.exists():
        raise SessionError("还没有保存的会话")
    try:
        data = json.loads(data_path.read_text("utf-8"))
    except (OSError, ValueError) as exc:
        raise SessionError("保存的会话文件损坏") from exc

    device_id = str(data.get("device_id") or "")
    if not device_id:
        raise SessionError("保存的会话缺少终端 ID")

    portal = Portal(cfg.server, cfg.port)
    for cookie in data.get("cookies") or []:
        host = cookie.get("host") or cfg.server
        portal.session.cookies.set(
            cookie["name"], cookie["value"], domain=host, path="/"
        )

    try:
        config = portal.auth_config(mod=True)
    except (PortalError, OSError) as exc:
        raise SessionError(f"会话检查失败：{exc}") from exc
    if int(config.get("isLogin") or 0) != 1:
        raise SessionError("学校会话已过期")

    try:
        resource = portal._api(
            "POST", "/controller/v1/user/clientResource", json=RESOURCE_REQUEST
        )
    except (PortalError, OSError) as exc:
        raise SessionError(f"刷新应用资源失败：{exc}") from exc

    app_data = ((resource.get("data") or {}).get("appList") or {}).get("data") or {}
    if not (app_data.get("config") or {}).get("nodeGroupConf"):
        raise SessionError("当前会话没有可用的隧道节点")

    sid = ""
    for cookie in portal.session.cookies:
        if cookie.name == "sid" and cfg.server in (cookie.domain or ""):
            sid = cookie.value
            break
    if not sid:
        raise SessionError("会话里没有 sid cookie")

    resource_path.write_text(json.dumps(resource, ensure_ascii=False), "utf-8")
    data["cookies"] = _cookies_for(portal, cfg.server)
    data["device_id"] = device_id
    data_path.write_text(json.dumps(data, ensure_ascii=False), "utf-8")
    return sid, device_id, str(resource_path)
