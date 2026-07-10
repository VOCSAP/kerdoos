"""Signed session cookie transport (HMAC-SHA256).

The opaque 256-bit session id (minted by AuthService, stored server-side only as
sha256) is carried to the browser in a cookie SIGNED with the app's session
secret, so a client cannot forge or tamper with it. This is the transport layer:
the trust decision (is this session still valid? is the owner active?) stays in
AuthService.verify_session (which resolves by sha256(session_id) and filters
owners.state='active' inline).

Cookie value format: "<session_id>.<hex_hmac>". read() recomputes the HMAC over
session_id with the secret and compares in constant time (hmac.compare_digest);
any mismatch -> None (rejected), so a tampered id never reaches AuthService.
"""

from __future__ import annotations

import hashlib
import hmac

COOKIE_NAME = "kerdoos_session"


class SessionCookie:
    def __init__(self, secret: str, *, secure: bool = True) -> None:
        if not secret:
            raise ValueError("session cookie secret must not be empty")
        self._key = secret.encode("utf-8")
        self._secure = secure

    def _sign(self, session_id: str) -> str:
        return hmac.new(
            self._key, session_id.encode("utf-8"), hashlib.sha256).hexdigest()

    def issue(self, session_id: str) -> str:
        """Return the signed cookie VALUE for a session id."""
        return f"{session_id}.{self._sign(session_id)}"

    def read(self, cookie_value: str | None) -> str | None:
        """Validate the signature and return the session id, or None if the
        cookie is absent/malformed/tampered."""
        if not cookie_value or "." not in cookie_value:
            return None
        session_id, _, signature = cookie_value.rpartition(".")
        if not session_id or not signature:
            return None
        expected = self._sign(session_id)
        # Constant-time comparison: no early-exit timing leak on the signature.
        if not hmac.compare_digest(expected, signature):
            return None
        return session_id

    def set_kwargs(self, cookie_value: str, max_age: int) -> dict:
        """kwargs for Response.set_cookie -- HttpOnly + SameSite=Lax + Secure
        (Secure configurable for a plain-http LAN deployment)."""
        return {
            "key": COOKIE_NAME,
            "value": cookie_value,
            "max_age": max_age,
            "httponly": True,
            "samesite": "lax",
            "secure": self._secure,
            "path": "/",
        }

    def clear_kwargs(self) -> dict:
        """kwargs for Response.delete_cookie on logout."""
        return {
            "key": COOKIE_NAME,
            "httponly": True,
            "samesite": "lax",
            "secure": self._secure,
            "path": "/",
        }
