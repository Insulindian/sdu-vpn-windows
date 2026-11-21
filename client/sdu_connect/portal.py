"""Minimal aTrust portal client: enough to discover the auth chain."""

from __future__ import annotations

import json
import base64
import platform
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse, parse_qs

import requests

from .endpoint import collect_endpoint, EndpointError
from .report_signature import sign_report
from .request_signature import derive_request_key, sign_request

BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
)

# Match the protocol implementation shipped in bin/zju-connect. These headers
# alone do not implement native endpoint enrollment or attestation.
LINUX_CLIENT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "aTrustTray/2.4.10.50 Chrome/83.0.4103.94 Electron/9.0.2 Safari/537.36 "
    "aTrustTray-Linux-Plat-Ubuntu-x64 SPCClientType"
)
WINDOWS_CLIENT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/138.0.0.0 Safari/537.36 "
    "aTrustTray/2.3.10.27301 aTrustTray-Windows-Plat SPCClientType"
)

_SYSTEM = platform.system()
if _SYSTEM == "Darwin":
    CLIENT_UA = BROWSER_UA + " sdu-connect/0.2.0 aTrustTray-MacOS-Plat SPCClientType"
elif _SYSTEM == "Windows":
    CLIENT_UA = WINDOWS_CLIENT_UA
else:
    CLIENT_UA = LINUX_CLIENT_UA

CLIENT_PARAMS = {
    "platform": {"Darwin": "Mac", "Windows": "Windows"}.get(_SYSTEM, "Linux"),
    "clientType": "SDPClient", "lang": "zh-CN",
}


class PortalError(RuntimeError):
    pass


@dataclass
class AuthServer:
    login_domain: str
    auth_type: str
    auth_name: str
    login_url: str

    @property
    def is_cas(self) -> bool:
        return self.auth_type == "auth/cas"


class Portal:
    def __init__(
        self,
        server: str = "vpn.sdu.edu.cn",
        port: int = 443,
        timeout: float = 20.0,
        debug: bool = False,
    ) -> None:
        host = server if port in (0, 443) else f"{server}:{port}"
        self.base = f"https://{host}"
        self.timeout = timeout
        self.debug = debug
        self.session = requests.Session()
        self._report_random = ""
        self._request_key: bytes | None = None
        self.session.headers.update(
            {
                "User-Agent": CLIENT_UA,
                "x-sdp-rid": base64.b64encode(urlparse(self.base).netloc.encode()).decode(),
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "zh-CN,zh;q=0.9",
            }
        )

    def _log(self, message: str) -> None:
        if self.debug:
            print(f"[portal] {message}")

    def auth_config(self, *, mod: bool = False, need_ticket: bool = True) -> dict[str, Any]:
        url = f"{self.base}/passport/v1/public/authConfig"
        params = dict(CLIENT_PARAMS)
        if need_ticket:
            params["needTicket"] = 1
        if mod:
            params["mod"] = 1
        response = self.session.get(url, params=params, timeout=self.timeout)
        self._log(f"GET authConfig -> {response.status_code}")
        response.raise_for_status()
        try:
            payload = response.json()
        except json.JSONDecodeError as exc:
            raise PortalError(f"authConfig 返回的不是 JSON: {response.text[:200]}") from exc

        if payload.get("code") != 0:
            raise PortalError(f"authConfig 失败: {payload.get('message')!r}")

        data = payload["data"]
        csrf = data.get("csrfToken") or (data.get("security") or {}).get("csrfToken")
        if csrf:
            self.session.headers["x-csrf-token"] = csrf
        anti_mitm = data.get("antiMITMAttackData") or {}
        self._request_key = None
        if isinstance(anti_mitm, dict):
            fields = [anti_mitm.get(k) for k in ("devicePubKeyMod", "devicePubKeyExp", "challenge")]
            if all(isinstance(v, str) and v for v in fields):
                self._request_key = derive_request_key(*fields)
                self._log("authConfig: negotiated in-memory request signing key")
        return data

    @staticmethod
    def auth_servers(config: dict[str, Any]) -> list[AuthServer]:
        return [
            AuthServer(
                login_domain=item.get("loginDomain", ""),
                auth_type=item.get("authType", ""),
                auth_name=item.get("authName", ""),
                login_url=item.get("loginUrl", ""),
            )
            for item in config.get("authServerInfoList", [])
        ]

    def cas_server(self, config: dict[str, Any]) -> AuthServer:
        for item in self.auth_servers(config):
            if item.is_cas:
                return item
        raise PortalError("服务端没有启用 CAS 认证（auth/cas）")

    def cas_login_url(self, config: dict[str, Any]) -> str:
        """Ask the portal where CAS lives; it points at the pre-login reverse proxy."""
        url = f"{self.base}/passport/v1/public/casLogin"
        response = self.session.get(url, params=CLIENT_PARAMS, allow_redirects=False, timeout=self.timeout)
        self._log(f"GET casLogin -> {response.status_code}")
        location = response.headers.get("Location")
        if location:
            return urljoin(self.base, location)

        # Fall back to the value advertised in authConfig.
        server = self.cas_server(config)
        if server.login_url:
            return f"{self.base}{server.login_url}"
        raise PortalError("无法获得 CAS 登录地址")

    def _api(self, method: str, path: str, **kwargs) -> dict[str, Any]:
        params = {**CLIENT_PARAMS, **kwargs.pop("query", {})}
        if platform.system() in ("Darwin", "Windows") and path.startswith("/controller/"):
            # Observed native transport headers; browser-facing CAS requests
            # retain their separate portal headers.
            params.pop("lang", None)
            kwargs["headers"] = {
                "User-Agent": "SPCClientType aTrustTray", "Accept": "*/*",
                "Accept-Language": None, "x-sdp-rid": None,
                "x-csrf-token": None, "x-sdp-traceid": uuid.uuid4().hex[:8],
                **kwargs.get("headers", {}),
            }
        if path in ("/controller/v1/public/reportEnv", "/controller/v1/user/reportEnv"):
            if not self._report_random:
                raise PortalError("环境策略响应缺少 x-sdp-random，不能签名上报")
            body = json.dumps(kwargs.pop("json"), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            kwargs["data"] = body
            kwargs["headers"] = {
                **kwargs.get("headers", {}), "Content-Type": "application/json",
                "x-sdp-signature": sign_report(self._report_random, body),
            }
        if self._request_key:
            # Sign the URL query and exact entity bytes, including for APIs
            # other than reportEnv. This is separate from x-sdp-signature.
            if "json" in kwargs:
                kwargs["data"] = json.dumps(kwargs.pop("json"), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                kwargs["headers"] = {**kwargs.get("headers", {}), "Content-Type": "application/json"}
            prepared = self.session.prepare_request(requests.Request(
                method, self.base + path, params=params,
                data=kwargs.get("data"), headers=kwargs.get("headers"),
            ))
            entity = prepared.body or b""
            if isinstance(entity, str):
                entity = entity.encode("utf-8")
            kwargs["headers"] = {
                **kwargs.get("headers", {}),
                "X-Request-Sig": sign_request(self._request_key, prepared.path_url, entity),
            }
        response = self.session.request(
            method, self.base + path, params=params,
            timeout=self.timeout, allow_redirects=False, **kwargs,
        )
        nonce = response.headers.get("x-sdp-random")
        if nonce:
            self._report_random = nonce
            self._log(f"{path}: nonce length={len(nonce)}, trimmed={nonce == nonce.strip()}, ascii={nonce.isascii()}")
        try:
            payload = response.json()
        except ValueError as exc:
            raise PortalError(f"{path}: HTTP {response.status_code}，返回非 JSON") from exc
        if not isinstance(payload, dict):
            raise PortalError(f"{path}: 响应结构错误")
        code = payload.get("code")
        if response.status_code != 200 or code != 0:
            hint = ""
            if code == 75500503:
                hint = (
                    "；服务端仍拒绝当前终端报告，需要继续核对绑定策略和终端证明；"
                    "不能视为 CAS 密码错误，也不会跳过终端认证"
                )
                # Keep actionable protocol metadata without dumping the response,
                # whose other fields can contain tickets or account information.
                data = payload.get("data")
                if isinstance(data, dict):
                    next_service = data.get("nextService")
                    if next_service in {
                        "auth/bindAuthDevice", "auth/accessCheck", "auth/authCheck",
                        "auth/sms", "auth/totp", "auth/radius",
                    }:
                        hint += f"；服务端下一步：{next_service}"
            raise PortalError(
                f"{path}: HTTP {response.status_code}, code={code}, "
                f"{payload.get('message', '')}{hint}"
            )
        return payload

    def complete_cas(self, domain: str, ticket: str, device_id: str) -> dict[str, Any]:
        """Consume a CAS ST once, then complete the client authentication chain.

        CAS ST, environment ticket and sidTicket serve different purposes.
        Never try them interchangeably or manufacture a signed SID cookie.
        """
        response = self.session.get(
            self.base + "/passport/v1/auth/cas",
            params={**CLIENT_PARAMS, "sfDomain": domain, "ticket": ticket},
            timeout=self.timeout, allow_redirects=False,
        )
        if response.status_code != 302:
            raise PortalError(f"CAS 回调: HTTP {response.status_code}，需要新的未消费票据")
        callback = urlparse(urljoin(self.base, response.headers.get("Location", "")))
        origin = urlparse(self.base)
        if (callback.scheme, callback.hostname, callback.port or 443) != (
            origin.scheme, origin.hostname, origin.port or 443
        ) or callback.path != "/portal/shortcut.html":
            raise PortalError("CAS 回调未返回本门户 shortcut；不跟随未知跳转")
        try:
            data = json.loads(parse_qs(callback.query).get("data", [""])[0])
            env_ticket = data["ticket"]
        except (ValueError, KeyError, TypeError) as exc:
            raise PortalError("CAS 回调缺少客户端环境票据；请重新登录") from exc
        if not isinstance(env_ticket, str) or not env_ticket:
            raise PortalError("CAS 环境票据为空")
        environment = data.get("env") or {}
        if isinstance(environment, dict):
            timing = environment.get("timing")
            self._log(f"CAS env fields={list(environment)}, timing={timing!r}" if timing in (
                None, "pre-login", "post-login", "before-login", "after-login",
                "login", "preLogin", "beforeLogin", "login-before",
            ) else f"CAS env fields={list(environment)}, timing=unrecognized")

        # Refresh the CSRF token after CAS, before reporting the environment.
        self.auth_config(mod=True, need_ticket=False)
        strategy = self._api(
            "GET", "/controller/v1/public/endpointStrategy",
            query={"timing": "pre-login", "ticket": env_ticket},
        ).get("data") or {}
        if strategy.get("reportItems"):
            raise PortalError("学校要求额外终端上报项目，当前未实现；停止认证")
        if not isinstance(strategy.get("env", []), list):
            raise PortalError("endpointStrategy.env 响应格式错误")
        try:
            endpoint = collect_endpoint(device_id, strategy.get("env", []))
        except EndpointError as exc:
            raise PortalError(str(exc)) from exc
        report_ticket = strategy.get("ticket") or env_ticket
        self._api("POST", "/controller/v1/public/reportEnv", json={
            "ticket": report_ticket, "deviceId": device_id,
            "timing": "pre-login",
            "env": {"endpoint": endpoint},
        })
        result = self._api("GET", "/passport/v1/auth/authCheck")
        step = result.get("data") or {}
        if step.get("nextService"):
            raise PortalError(
                f"需要后续认证步骤 {step['nextService']}；当前会话尚不能启动隧道"
            )
        # Only exchange an explicit sidTicket returned by authentication.
        if step.get("sidTicket"):
            self._api("POST", "/passport/v1/public/sessionIdExchange",
                      json={"sidTicket": step["sidTicket"]})
        if self.auth_config(mod=True, need_ticket=False).get("isLogin") != 1:
            raise PortalError("authCheck 后 isLogin != 1；未形成已认证的客户端会话")
        return self._api("POST", "/controller/v1/user/clientResource", json={
            "resourceType": {"sdpPolicy": {}, "appList": {}, "favoriteAppList": {},
                             "featureCenter": {}, "uemSpace": {"params": {"action": "login"}}},
        })
