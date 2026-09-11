"""AuthService -- identity resolution + sessions + bearer tokens (ADR 0001 S6).

Core use-case layer for auth. Depends ONLY on ports (auth.ports.AuthStore,
auth.ports.PasswordHasher) plus the same-package Principal; the concrete
Argon2Hasher + SqliteAuthStore are injected by the composition root (CLI).

Security invariants enforced here:
  * Principal.role is ALWAYS server-resolved (read from owners.role via the
    store), NEVER taken from client input (Phase 1 finding L2).
  * a disabled owner (owners.state != 'active') is cut off: the store applies
    the state filter INLINE in every resolve/lookup, so a still-valid
    session/token for a disabled owner resolves to None.
  * login is anti-enumeration: authenticate() pays EXACTLY ONE Argon2id verify
    on every failure branch (unknown identifier, NULL password_hash, wrong
    password) and returns a uniform None, so neither the response nor the
    latency leaks whether an account exists (rule FastAPI anti-enum).
  * create_token() mints ONLY for the acting principal (no target-owner
    parameter exists), so an admin cannot mint a token for another owner
    (Kleos #11060/#11064). revoke_all(target) is admin-only when target!=self.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from kerdoos.auth.ports import AuthStore, PasswordHasher, TokenInfo
from kerdoos.core.app.services import Principal

# High-entropy opaque secrets (session id / bearer token). 256 bits of
# randomness -> unguessable; the token is never stored in the clear (only its
# SHA-256), so a config.db leak does not yield usable bearer tokens.
_SECRET_BYTES = 32
DEFAULT_SESSION_TTL = timedelta(days=14)
DEFAULT_TOKEN_TTL = timedelta(days=90)

# Basic format check only (not RFC 5322): "something@something.tld". The
# store enforces real uniqueness; this just rejects obviously-malformed input
# before it ever reaches SQL. Also excludes , ; < > " ( ) -- roadmap
# f3b644ab gate C1: a comma in the local part passed the old pattern and
# let a stored value be reinterpreted as TWO recipients once placed in an
# email "To" header (digest.smtp_sender's retry-safety reasoning assumes
# exactly one recipient); the other characters can forge address/header
# structure the same way.
#
# The domain part is restricted to dot-separated DNS labels
# ([A-Za-z0-9-]+, punycode xn-- included), narrower than the local part's
# negated class -- roadmap 4a8afdf2: a bracketed IP-address literal
# (a@[10.0.0.1]) would let a tenant make the configured SMTP relay connect
# to an arbitrary host on port 25 (SSRF against the relay's own network
# reach). The final label must start with a letter (or be an xn-- punycode
# label) -- an all-numeric final label (a@10.0.0.1, a@2130706433.1) is not
# a real TLD and can itself encode an IP address, the same SSRF surface
# under a different notation.
_EMAIL_RE = re.compile(
    r'^[^@\s,;<>"()]+@(?:[A-Za-z0-9-]+\.)+'
    r'(?:[A-Za-z][A-Za-z0-9-]*|xn--[A-Za-z0-9-]+)$')


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class IssuedToken:
    """A freshly minted bearer token. `token` is the ONLY time the plaintext is
    available (the store keeps only its hash); `token_id` labels it for
    revocation."""

    token_id: str
    token: str


class AuthService:
    def __init__(
        self,
        store: AuthStore,
        hasher: PasswordHasher,
        *,
        session_ttl: timedelta = DEFAULT_SESSION_TTL,
        token_ttl: timedelta = DEFAULT_TOKEN_TTL,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._store = store
        self._hasher = hasher
        self._session_ttl = session_ttl
        self._token_ttl = token_ttl
        self._clock = clock

    @property
    def session_ttl_seconds(self) -> int:
        """Session lifetime in seconds (for the cookie Max-Age)."""
        return int(self._session_ttl.total_seconds())

    # -- login (anti-enumeration) -----------------------------------------
    def authenticate(self, identifier: str, password: str) -> Principal | None:
        """Resolve an owner by name OR email and verify the password.

        Every failure branch pays exactly one Argon2id verify and returns None,
        so account existence never leaks via response or timing.
        """
        creds = self._store.lookup_active_credentials(identifier)
        if creds is None:
            # Unknown identifier (or disabled owner) -> dummy verify, uniform cost.
            self._hasher.dummy_verify(password)
            return None
        if creds.password_hash is None:
            # Passwordless owner -> dummy verify (NOT a fast reject), uniform cost.
            self._hasher.dummy_verify(password)
            return None
        if not self._hasher.verify(creds.password_hash, password):
            return None
        # role is server-resolved from owners.role, never from input.
        return Principal(owner_id=creds.owner_id, role=creds.role)

    def check_and_authenticate(
        self, identifier: str, password: str,
    ) -> tuple[Principal | None, float | None]:
        """authenticate() wrapped with a persistent, per-identifier rate
        limit (roadmap f1048ab8). Returns (principal, retry_after): when
        retry_after is not None, the identifier is currently blocked and
        principal is always None -- authenticate() is never called (no
        Argon2id cost paid, no credential check at all) while blocked,
        even for a correct password. The rate-limit KEY is the identifier
        as typed (normalized), never resolved to an owner_id, so a
        nonexistent identifier is throttled identically to a real one."""
        key = identifier.strip().lower()
        now = self._clock().timestamp()
        # The reservation counts this ATTEMPT before its outcome is known
        # (closes a check-then-record race under concurrent requests): a
        # successful authenticate() below still resets the counter.
        retry_after = self._store.reserve_login_attempt(key, now=now)
        if retry_after is not None:
            return None, retry_after
        principal = self.authenticate(identifier, password)
        if principal is not None:
            self._store.record_login_success(key)
        return principal, None

    # -- sessions (WebUI) --------------------------------------------------
    def create_session(self, principal: Principal) -> str:
        """Mint a revocable session for the acting principal. Returns the opaque
        session id (the WebUI wraps it in a signed cookie at the transport
        layer, Phase 4). Only sha256(session_id) is persisted, so a config.db
        leak never yields a usable session id."""
        session_id = secrets.token_urlsafe(_SECRET_BYTES)
        now = self._clock()
        self._store.create_session(
            _token_hash(session_id), principal.owner_id,
            now.isoformat(), (now + self._session_ttl).isoformat())
        return session_id

    def verify_session(self, session_id: str) -> Principal | None:
        identity = self._store.resolve_session(
            _token_hash(session_id), self._clock().isoformat())
        if identity is None:
            return None
        return Principal(owner_id=identity.owner_id, role=identity.role)

    def revoke_session(self, principal: Principal, session_id: str) -> None:
        # Delete by hash (the plaintext id is an unguessable secret held only by
        # its owner; the DB only ever stored its sha256).
        self._store.delete_session(_token_hash(session_id))

    # -- bearer tokens (MCP) ----------------------------------------------
    def create_token(self, principal: Principal) -> IssuedToken:
        """Mint a bearer token FOR THE ACTING PRINCIPAL ONLY.

        There is deliberately NO target-owner parameter: an admin can only mint
        a token for itself, never for another owner (no usurpation via an
        admin-minted token -- Kleos #11060/#11064).
        """
        token = secrets.token_urlsafe(_SECRET_BYTES)
        token_id = secrets.token_hex(8)
        now = self._clock()
        self._store.create_token(
            _token_hash(token), token_id, principal.owner_id,
            now.isoformat(), (now + self._token_ttl).isoformat())
        return IssuedToken(token_id=token_id, token=token)

    def verify_bearer(self, token: str) -> Principal | None:
        identity = self._store.resolve_token(
            _token_hash(token), self._clock().isoformat())
        if identity is None:
            return None
        return Principal(owner_id=identity.owner_id, role=identity.role)

    def revoke_token(self, principal: Principal, token_id: str) -> None:
        """Revoke one of the acting principal's own tokens (scoped by
        owner_id, so a principal cannot revoke another owner's token by id)."""
        self._store.revoke_token(principal.owner_id, token_id)

    def revoke_all(self, principal: Principal, target_owner_id: str) -> None:
        """Revoke ALL sessions + tokens of target_owner_id.

        Self-service for one's own account; admin-only when target != self (an
        admin can cut any account but never create access for a third party).
        """
        if target_owner_id != principal.owner_id and principal.role != "admin":
            raise PermissionError(
                f"principal {principal.owner_id!r} (role={principal.role!r}) "
                f"may not revoke access for owner {target_owner_id!r}"
            )
        self._store.delete_owner_sessions(target_owner_id)
        self._store.revoke_owner_tokens(target_owner_id)

    # -- self-service profile (WebUI Phase 4b) ------------------------------
    def get_email(self, principal: Principal) -> str | None:
        """Read the ACTING principal's own email (self-scope strict -- no
        target-owner parameter, mirroring set_email/list_tokens). Used to
        pre-fill the profile form; returns None if never set."""
        return self._store.get_email(principal.owner_id)

    def set_email(self, principal: Principal, email: str | None) -> None:
        """Set or clear the ACTING principal's own email (self-scope strict --
        there is deliberately no target-owner parameter, mirroring
        create_token/revoke_token: a principal can only ever touch its own
        row). email=None removes it (owners.email is nullable by design, cf.
        the identity ADR).

        Raises ValueError on an obviously malformed non-None email, or
        EmailAlreadyTakenError (from the store) if a different owner already
        has that email -- never a raw sqlite3.IntegrityError.
        """
        if email is not None and not _EMAIL_RE.fullmatch(email):
            raise ValueError(f"invalid email format: {email!r}")
        self._store.set_email(principal.owner_id, email)

    def list_tokens(self, principal: Principal) -> list[TokenInfo]:
        """List the ACTING principal's own active, not-yet-expired bearer
        tokens (self-scope strict), most recent first. An expired-but-not-
        revoked token no longer appears (clock-consistent with
        verify_bearer). Never returns the plaintext token or its hash --
        only enough to label + revoke via revoke_token(principal, token_id)."""
        return self._store.list_tokens(principal.owner_id, self._clock().isoformat())
