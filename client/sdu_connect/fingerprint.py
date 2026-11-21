"""Stable pseudo-device identity for the CAS second-factor flow.

SDU CAS binds the "trust this device" flag to a fingerprint that the login page
computes with Fingerprint2.  The exact contents do not matter as long as they
never change between logins: the first login registers the fingerprint (SMS
required), later logins are recognised and skip the SMS.

We therefore synthesise a plausible Fingerprint2 component set once, persist it
under ``~/.config/sdu-connect/device.json`` and reuse it forever.  ``new-device``
rotates it, which deliberately costs one more SMS.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from .des import str_enc

_MASK = (1 << 64) - 1


def murmur_x64_128(data: bytes, seed: int = 31) -> str:
    """MurmurHash3 x64 128, matching Fingerprint2.x64hash128 on ASCII input."""

    def rotl(value: int, bits: int) -> int:
        return ((value << bits) | (value >> (64 - bits))) & _MASK

    def fmix(value: int) -> int:
        value ^= value >> 33
        value = (value * 0xFF51AFD7ED558CCD) & _MASK
        value ^= value >> 33
        value = (value * 0xC4CEB9FE1A85EC53) & _MASK
        value ^= value >> 33
        return value

    c1 = 0x87C37B91114253D5
    c2 = 0x4CF5AD432745937F
    h1 = h2 = seed & _MASK

    blocks = len(data) // 16
    for index in range(blocks):
        chunk = data[index * 16 : index * 16 + 16]
        k1 = int.from_bytes(chunk[:8], "little")
        k2 = int.from_bytes(chunk[8:], "little")

        k1 = (k1 * c1) & _MASK
        k1 = rotl(k1, 31)
        k1 = (k1 * c2) & _MASK
        h1 ^= k1
        h1 = rotl(h1, 27)
        h1 = (h1 + h2) & _MASK
        h1 = (h1 * 5 + 0x52DCE729) & _MASK

        k2 = (k2 * c2) & _MASK
        k2 = rotl(k2, 33)
        k2 = (k2 * c1) & _MASK
        h2 ^= k2
        h2 = rotl(h2, 31)
        h2 = (h2 + h1) & _MASK
        h2 = (h2 * 5 + 0x38495AB5) & _MASK

    tail = data[blocks * 16 :]
    k1 = k2 = 0
    for i, byte in enumerate(tail[:8]):
        k1 |= byte << (8 * i)
    for i, byte in enumerate(tail[8:]):
        k2 |= byte << (8 * i)

    if len(tail) > 8:
        k2 = (k2 * c2) & _MASK
        k2 = rotl(k2, 33)
        k2 = (k2 * c1) & _MASK
        h2 ^= k2
    if tail:
        k1 = (k1 * c1) & _MASK
        k1 = rotl(k1, 31)
        k1 = (k1 * c2) & _MASK
        h1 ^= k1

    length = len(data)
    h1 ^= length
    h2 ^= length
    h1 = (h1 + h2) & _MASK
    h2 = (h2 + h1) & _MASK
    h1 = fmix(h1)
    h2 = fmix(h2)
    h1 = (h1 + h2) & _MASK
    h2 = (h2 + h1) & _MASK
    return f"{h1:016x}{h2:016x}"


# Fingerprint2 component order, with values a long-lived macOS Chrome install
# would plausibly produce.  Only ``details_s`` / ``details_browser_s`` are used.
_COMPONENTS: list[tuple[str, object]] = [
    ("userAgent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"),
    ("language", "zh-CN"),
    ("colorDepth", 30),
    ("deviceMemory", 8),
    ("pixelRatio", 2),
    ("hardwareConcurrency", 10),
    ("screenResolution", [1728, 1117]),
    ("availableScreenResolution", [1728, 1055]),
    ("timezoneOffset", -480),
    ("timezone", "Asia/Shanghai"),
    ("sessionStorage", True),
    ("localStorage", True),
    ("indexedDb", True),
    ("addBehavior", False),
    ("openDatabase", False),
    ("cpuClass", "not available"),
    ("platform", "MacIntel"),
    ("doNotTrack", "not available"),
    ("plugins", ["PDF Viewer", "Chrome PDF Viewer", "Chromium PDF Viewer", "Microsoft Edge PDF Viewer", "WebKit built-in PDF"]),
    ("canvas", "8d1a9c0f6b7e2a4c"),
    ("webgl", "b1f0c7d2e8a9"),
    ("webglVendorAndRenderer", "Google Inc. (Apple)~ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)"),
    ("adBlock", False),
    ("hasLiedLanguages", False),
    ("hasLiedResolution", False),
    ("hasLiedOs", False),
    ("hasLiedBrowser", False),
    ("touchSupport", [0, False, False]),
    ("fonts", ["Arial", "Helvetica", "Helvetica Neue", "Menlo", "Monaco", "PingFang SC", "Songti SC"]),
    ("audio", 124.04347527516074),
]

_SKIP_DEVICE = {"deviceMemory", "screenResolution", "availableScreenResolution"}
_SKIP_BROWSER = _SKIP_DEVICE | {"browserVersion"}
_STABLE_UA_KEY = "Chrome/Mac OS/x86_64"


def _line(key: str, value: object) -> str:
    if isinstance(value, list):
        rendered = ";".join(str(item) for item in value)
    elif isinstance(value, bool):
        rendered = "true" if value else "false"
    else:
        rendered = str(value)
    return f"{key} = {rendered[:100]}\n"


def build_details(skip: set[str] | None = None, stable_ua: bool = False) -> str:
    parts = []
    for key, value in _COMPONENTS:
        if skip and key in skip:
            continue
        if stable_ua and key == "userAgent":
            value = _STABLE_UA_KEY
        parts.append(_line(key, value))
    return "".join(parts)


@dataclass
class DeviceIdentity:
    """Everything the CAS page would have computed in the browser."""

    details: str
    details_browser: str
    full: str
    murmur: str
    murmur_s: str
    d_md5: str
    d_browser_md5: str
    i: str

    def as_payload_m1(self, username: str, password: str) -> dict[str, str]:
        return {
            "d": self.murmur,
            "d_s": self.murmur_s,
            "d_md5": self.d_md5,
            "d_browser_md5": self.d_browser_md5,
            "i": self.i,
            "m": "1",
            "u": str_enc(username),
            "p": str_enc(password),
        }

    def as_payload_m3(self, username: str, code: str, save: bool) -> dict[str, str]:
        return {
            "d": self.murmur_s,
            "i": self.details,
            "m": "3",
            "u": username,
            "c": code,
            "s": "1" if save else "0",
        }

    def to_json(self) -> str:
        return json.dumps({"details": self.details}, ensure_ascii=False, indent=2)

    @classmethod
    def from_details(cls, details: str) -> "DeviceIdentity":
        details_browser = build_details(_SKIP_BROWSER, stable_ua=True)
        full = build_details()
        return cls(
            details=details,
            details_browser=details_browser,
            full=full,
            murmur=murmur_x64_128(full.encode("latin-1", "replace")),
            murmur_s=murmur_x64_128(details.encode("latin-1", "replace")),
            d_md5=str_enc(hashlib.md5(details.encode("utf-8")).hexdigest()),
            d_browser_md5=str_enc(hashlib.md5(details_browser.encode("utf-8")).hexdigest()),
            i=str_enc(details),
        )

    @classmethod
    def generate(cls) -> "DeviceIdentity":
        return cls.from_details(build_details(_SKIP_DEVICE))

    @classmethod
    def load(cls, path: Path) -> "DeviceIdentity | None":
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text("utf-8"))
            details = data["details"]
        except (OSError, ValueError, KeyError):
            return None
        # Recompute everything but keep the registered string byte-identical.
        return cls.from_details(details)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json(), "utf-8")
