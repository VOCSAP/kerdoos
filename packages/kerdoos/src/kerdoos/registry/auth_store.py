"""SqliteAuthStore + Argon2Hasher -- concurrent-safe auth adapter (Phase 3).

CONCURRENCY INVARIANT (architect FD3, ADR 0001 S5.1): every method opens its
OWN short-lived connection to config.db (connection-per-operation) and closes
it. The auth store NEVER shares SqliteConfigStore's single self._conn, so the
verify_* path -- INCLUDING the SELECT on the owners table for state/role/
password_hash -- is safe under concurrent ASGI handlers with no
sqlite3.ProgrammingError and no head-of-line global lock. WAL journal mode +
busy_timeout mean a concurrent login write never blocks readers ("ni
head-of-line lock").

The owners TABLE itself is owned/created by SqliteConfigStore; this store only
creates sessions/tokens and READS owners. Construct a SqliteConfigStore on the
same path first (composition root / tests) so owners exists.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from argon2 import PasswordHasher as _Argon2PH
from argon2.exceptions import Argon2Error, VerifyMismatchError

from kerdoos.auth.ports import OwnerCredentials, ResolvedIdentity

_SESSION_TOKEN_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_hash TEXT PRIMARY KEY,
    owner_id     TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_owner ON sessions(owner_id);

CREATE TABLE IF NOT EXISTS tokens (
    token_hash TEXT PRIMARY KEY,
    id         TEXT NOT NULL,
    owner_id   TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    state      TEXT NOT NULL DEFAULT 'active'
);
CREATE INDEX IF NOT EXISTS idx_tokens_owner ON tokens(owner_id);
"""

_BUSY_TIMEOUT_MS = 5000


class Argon2Hasher:
    """PasswordHasher port impl backed by argon2-cffi (Argon2id).

    The dummy hash is a real Argon2id digest computed once with the SAME
    parameters, so dummy_verify pays the same cost as a real verify -- the basis
    of the anti-enumeration guarantee.
    """

    def __init__(self) -> None:
        # Explicit Argon2id parameters (not library defaults, which shift
        # between releases): OWASP-aligned baseline -- 3 iterations, 64 MiB,
        # parallelism 4, 32-byte hash, 16-byte salt (gate security L2).
        self._ph = _Argon2PH(
            time_cost=3, memory_cost=64 * 1024, parallelism=4,
            hash_len=32, salt_len=16)
        # A fixed, real Argon2id hash of an unrelated secret; verifying against
        # it costs exactly one real verify without ever matching a user input.
        self._dummy_hash = self._ph.hash("kerdoos-anti-enumeration-dummy")

    def hash(self, password: str) -> str:
        return self._ph.hash(password)

    def verify(self, password_hash: str, password: str) -> bool:
        try:
            self._ph.verify(password_hash, password)
            return True
        except (VerifyMismatchError, Argon2Error):
            return False

    def dummy_verify(self, password: str) -> None:
        try:
            self._ph.verify(self._dummy_hash, password)
        except (VerifyMismatchError, Argon2Error):
            pass


class SqliteAuthStore:
    """AuthStore port impl on config.db, connection-per-operation (see module
    docstring). Thread-safe by construction: no shared connection, no lock."""

    def __init__(self, config_db_path: str | Path) -> None:
        self._path = str(config_db_path)
        # One-time: enable WAL (persists at the DB level) and ensure the
        # sessions/tokens tables exist. Owners is created by SqliteConfigStore.
        conn = self._connect()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SESSION_TOKEN_SCHEMA)
            conn.commit()
        finally:
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path)
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
        return conn

    # -- credential lookup (login) ----------------------------------------
    def lookup_active_credentials(self, identifier: str) -> OwnerCredentials | None:
        # Resolve by name FIRST, then by email -- as two separate lookups, NOT
        # a `name = ? OR email = ?` (which could match two different owners for
        # one identifier). name takes precedence, so an identifier resolves to
        # AT MOST one owner deterministically (gate L1).
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT id, role, password_hash FROM owners "
                "WHERE name = ? AND state = 'active'",
                (identifier,),
            ).fetchone()
            if row is None:
                row = conn.execute(
                    "SELECT id, role, password_hash FROM owners "
                    "WHERE email = ? AND state = 'active'",
                    (identifier,),
                ).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        return OwnerCredentials(
            owner_id=row["id"], role=row["role"],
            password_hash=row["password_hash"])

    # -- sessions ----------------------------------------------------------
    def create_session(
        self, session_hash: str, owner_id: str, created_at: str, expires_at: str
    ) -> None:
        # session_hash = sha256(session_id): only the hash is persisted, so a
        # config.db leak does not yield usable session ids (symmetry with
        # tokens; closes the hijack asymmetry, gate SESSION-HASH).
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO sessions (session_hash, owner_id, created_at, expires_at) "
                "VALUES (?, ?, ?, ?)",
                (session_hash, owner_id, created_at, expires_at),
            )
            conn.commit()
        finally:
            conn.close()

    def resolve_session(self, session_hash: str, now: str) -> ResolvedIdentity | None:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT o.id AS owner_id, o.role AS role "
                "FROM sessions s JOIN owners o ON o.id = s.owner_id "
                "WHERE s.session_hash = ? AND o.state = 'active' "
                "AND s.expires_at > ?",
                (session_hash, now),
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        return ResolvedIdentity(owner_id=row["owner_id"], role=row["role"])

    def delete_session(self, session_hash: str) -> None:
        conn = self._connect()
        try:
            conn.execute("DELETE FROM sessions WHERE session_hash = ?",
                         (session_hash,))
            conn.commit()
        finally:
            conn.close()

    def delete_owner_sessions(self, owner_id: str) -> None:
        conn = self._connect()
        try:
            conn.execute("DELETE FROM sessions WHERE owner_id = ?", (owner_id,))
            conn.commit()
        finally:
            conn.close()

    # -- bearer tokens -----------------------------------------------------
    def create_token(
        self, token_hash: str, token_id: str, owner_id: str,
        created_at: str, expires_at: str,
    ) -> None:
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO tokens "
                "(token_hash, id, owner_id, created_at, expires_at, state) "
                "VALUES (?, ?, ?, ?, ?, 'active')",
                (token_hash, token_id, owner_id, created_at, expires_at),
            )
            conn.commit()
        finally:
            conn.close()

    def resolve_token(self, token_hash: str, now: str) -> ResolvedIdentity | None:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT o.id AS owner_id, o.role AS role "
                "FROM tokens t JOIN owners o ON o.id = t.owner_id "
                "WHERE t.token_hash = ? AND t.state = 'active' "
                "AND o.state = 'active' AND t.expires_at > ?",
                (token_hash, now),
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        return ResolvedIdentity(owner_id=row["owner_id"], role=row["role"])

    def revoke_token(self, owner_id: str, token_id: str) -> None:
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE tokens SET state = 'disabled' "
                "WHERE owner_id = ? AND id = ?",
                (owner_id, token_id),
            )
            conn.commit()
        finally:
            conn.close()

    def revoke_owner_tokens(self, owner_id: str) -> None:
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE tokens SET state = 'disabled' WHERE owner_id = ?",
                (owner_id,),
            )
            conn.commit()
        finally:
            conn.close()
