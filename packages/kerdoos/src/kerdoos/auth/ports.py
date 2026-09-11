"""Auth ports: PasswordHasher + AuthStore (Protocols) + value objects.

Pure contracts (no concrete adapter, no argon2/sqlite import here). AuthService
(core.app.auth) depends only on these; the composition root injects the
concrete Argon2Hasher + SqliteAuthStore. Keeps the core free of tool imports,
mirroring the autolycos ports discipline.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class OwnerCredentials:
    """An ACTIVE owner's auth row, as read by the concurrent verify path.

    Only owners with state='active' are ever returned (the disabled-account cut
    is applied INLINE in the SQL, so a disabled owner looks like an unknown one
    to the caller). password_hash is None for a passwordless owner.
    """

    owner_id: str
    role: str
    password_hash: str | None


@dataclass(frozen=True, slots=True)
class ResolvedIdentity:
    """The (owner_id, role) a valid session/token resolves to. role is always
    read from owners.role server-side -- never from client input."""

    owner_id: str
    role: str


@dataclass(frozen=True, slots=True)
class TokenInfo:
    """One of a principal's own bearer tokens, for self-service listing
    (list_tokens). NEVER carries the plaintext token or its sha256 hash --
    only enough to label and revoke it by id (revoke_token(principal,
    token_id) already exists)."""

    token_id: str
    created_at: str
    expires_at: str


class EmailAlreadyTakenError(ValueError):
    """Raised by AuthStore.set_email when the requested email is already used
    by a DIFFERENT owner (idx_owners_email unique partial index collision,
    translated from sqlite3.IntegrityError -- never let it surface raw, cf.
    Kleos #11162). Kept in auth.ports rather than registry.errors.ConfigError
    so the auth module's error taxonomy stays self-contained (AuthService
    depends ONLY on auth.ports + same-package Principal)."""


@runtime_checkable
class PasswordHasher(Protocol):
    """Argon2id password hashing + a constant-cost dummy verify for anti-enum."""

    def hash(self, password: str) -> str:
        ...

    def verify(self, password_hash: str, password: str) -> bool:
        ...

    def dummy_verify(self, password: str) -> None:
        """Verify `password` against a fixed internal dummy hash and discard the
        result. Pays the SAME Argon2id cost as a real verify so the unknown /
        NULL-hash login branches are timing-indistinguishable (anti-enum)."""
        ...


@runtime_checkable
class AuthStore(Protocol):
    """Concurrent-safe (per-operation connection) identity/session/token store.

    EVERY method here runs the disabled-account guard (owners.state='active')
    INLINE in SQL, and every read of the owners table goes through this store's
    own per-op connection -- never the shared SqliteConfigStore connection
    (Phase 3 concurrency invariant, architect FD3).
    """

    # -- credential lookup (login) --
    def lookup_active_credentials(self, identifier: str) -> OwnerCredentials | None:
        """Resolve an ACTIVE owner by name OR email (hybrid identity). Returns
        None for an unknown OR disabled identifier (indistinguishable)."""
        ...

    # -- login rate-limit (roadmap f1048ab8) -- keyed by the identifier as
    # TYPED (normalized, never resolved to an owner_id), so behavior is
    # identical whether it names a real owner or not (anti-enumeration).
    def login_attempt_blocked_seconds(
        self, identifier_key: str, *, now: float,
    ) -> float | None:
        """None if identifier_key may attempt a login now. Otherwise the
        number of seconds to wait: either its own failure count has
        reached the configured max within the current window, or -- fail
        closed -- the table is at its row cap and identifier_key has no
        existing row to check (a flood of distinct identifiers must not
        grow the table without bound, nor silently disable the limit)."""
        ...

    def record_login_failure(self, identifier_key: str, *, now: float) -> None:
        """Increment identifier_key's failure count (creating its row if
        capacity allows), after purging any row whose window has
        expired."""
        ...

    def record_login_success(self, identifier_key: str) -> None:
        """Reset identifier_key's failure count to zero (deletes its
        row, if any)."""
        ...

    # -- sessions (WebUI) -- keyed by session_hash = sha256(session_id); only
    # the hash is ever persisted (the plaintext id lives only in the caller's
    # cookie), so a config.db leak yields no usable session.
    def create_session(
        self, session_hash: str, owner_id: str, created_at: str, expires_at: str
    ) -> None:
        ...

    def resolve_session(self, session_hash: str, now: str) -> ResolvedIdentity | None:
        """JOIN owners WHERE owners.state='active' AND expires_at > now, INLINE.
        None if missing/expired/owner-disabled."""
        ...

    def delete_session(self, session_hash: str) -> None:
        ...

    def delete_owner_sessions(self, owner_id: str) -> None:
        ...

    # -- bearer tokens (MCP) --
    def create_token(
        self, token_hash: str, token_id: str, owner_id: str,
        created_at: str, expires_at: str,
    ) -> None:
        ...

    def resolve_token(self, token_hash: str, now: str) -> ResolvedIdentity | None:
        """JOIN owners WHERE owners.state='active' AND tokens.state='active'
        AND expires_at > now, INLINE. None if missing/expired/revoked/disabled."""
        ...

    def revoke_token(self, owner_id: str, token_id: str) -> None:
        """Revoke one token BY its owner (owner_id scopes the update, so a
        principal can only revoke its own token by id)."""
        ...

    def revoke_owner_tokens(self, owner_id: str) -> None:
        ...

    # -- self-service profile (WebUI Phase 4b) --
    def get_email(self, owner_id: str) -> str | None:
        """Read owner_id's own email (None if never set or owner_id unknown --
        never raises for a missing row)."""
        ...

    def set_email(self, owner_id: str, email: str | None) -> None:
        """Set (email=str) or clear (email=None) owner_id's email. Raises
        EmailAlreadyTakenError if a DIFFERENT owner already has that email
        (idx_owners_email unique partial index)."""
        ...

    def list_tokens(self, owner_id: str, now: str) -> list[TokenInfo]:
        """List owner_id's own ACTIVE, NOT-YET-EXPIRED tokens (state='active'
        AND expires_at > now), most recent first (created_at DESC). `now`
        keeps the expiry cut consistent with resolve_token/resolve_session
        (caller-supplied clock, never read server time internally). Never
        includes the plaintext token or its hash."""
        ...
