"""Wire-compatible environment-report signature, using the session nonce.

The salt is a fixed protocol constant, not a user's credential. The nonce comes
from this client's own endpointStrategy response. Sign exactly the body bytes
that will be sent; never import a key or session from the official client.
"""
import hashlib
import hmac

_REPORT_SALT = b'oTFBYM#r^we@Hvj4'


def sign_report(nonce: str, body: bytes) -> str:
    if not nonce:
        raise ValueError('environment report nonce is empty')
    intermediate = hmac.new(nonce.encode('utf-8'), _REPORT_SALT, hashlib.sha256).hexdigest().upper()
    return hmac.new(intermediate.encode('ascii'), body, hashlib.sha256).hexdigest().upper()
