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

    # -- sessions (WebUI) --
    def create_session(
        self, session_id: str, owner_id: str, created_at: str, expires_at: str
    ) -> None:
        ...

    def resolve_session(self, session_id: str, now: str) -> ResolvedIdentity | None:
        """JOIN owners WHERE owners.state='active' AND expires_at > now, INLINE.
        None if missing/expired/owner-disabled."""
        ...

    def delete_session(self, session_id: str) -> None:
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
