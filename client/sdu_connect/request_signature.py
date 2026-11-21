"""Native request signature derived from this session's public challenge.

No official database or library is used at runtime. The salt is a fixed protocol
constant. Keys remain in memory and change with authConfig's challenge.
"""
import hashlib
import hmac

_REQUEST_SALT = '3uW5IEy8KwDaOMK8uw1TmNr50U3aK1Qdu8b6vopXxGstzan3AJXxVNR6piuKi5Nq'


def derive_request_key(modulus: str, exponent: str, challenge: str) -> bytes:
    seed = (modulus + exponent + _REQUEST_SALT).encode('utf-8')
    first = hashlib.sha256(seed).digest()
    second = hashlib.sha256((first.hex().upper() + challenge).encode('utf-8')).digest()
    return bytes(a ^ b for a, b in zip(first, second))


def sign_request(key: bytes, path_query: str, body: bytes = b'') -> str:
    return hmac.new(key, path_query.encode('utf-8') + body, hashlib.sha256).hexdigest().upper()
