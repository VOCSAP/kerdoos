"""SqliteAuthStore + Argon2Hasher -- concurrent-safe auth adapter (Phase 3).

CONCURRENCY INVARIANT (architect FD3, ADR 0001 S5.1): every method opens its
OWN short-lived connection to config.db (connection-per-operation) and closes
it. The auth store NEVER shares SqliteConfigStore's single self._conn, so the
verify_* path -- INCLUDING the SELECT on the owners table for state/role/
password_hash -- is safe under concurrent ASGI handlers with no
sqlite3.ProgrammingError and no head-of-line global lock. WAL journal mode +
busy_timeout mean a concurrent login write never blocks readers ("ni
head-of-line lock").

The owners TABLE itself is owned/created by SqliteConfigStore; this store
creates sessions/tokens, READS owners, and owns ONE explicitly-scoped write
path onto owners -- set_email (self-service profile field, Phase 4b). That
write is narrow (single column, single row by id) and does not change who
creates the table or its other columns. Construct a SqliteConfigStore on the
same path first (composition root / tests) so owners exists.

EMAIL UNIQUENESS INVARIANT (fast-follow hardening, Kleos architect finding
MEDIUM): __init__ ENSURES idx_owners_email itself (pre-check duplicates, then
CREATE UNIQUE INDEX IF NOT EXISTS) rather than relying on SqliteConfigStore
having run first. This writer owns its own invariant -- set_email's
EmailAlreadyTakenError translation no longer silently depends on wiring
order (Config-before-Auth). If owners does not exist yet (this store built
standalone, no SqliteConfigStore ever ran on this path), the check is
skipped silently; SqliteConfigStore's _migrate() creates the identical index
when it eventually runs. CREATE UNIQUE INDEX IF NOT EXISTS run redundantly by
both stores is idempotent and safe.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from argon2 import PasswordHasher as _Argon2PH
from argon2.exceptions import Argon2Error, VerifyMismatchError

from kerdoos.auth.ports import (
    EmailAlreadyTakenError,
    OwnerCredentials,
    ResolvedIdentity,
    TokenInfo,
)

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

-- roadmap f1048ab8: keyed by the identifier as TYPED (normalized), never
-- an owner_id -- no FK to owners, a row can exist for an identifier that
-- names no real owner at all.
CREATE TABLE IF NOT EXISTS login_attempts (
    identifier_key TEXT PRIMARY KEY,
    failure_count  INTEGER NOT NULL,
    window_start   REAL NOT NULL
);
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

    def __init__(
        self, config_db_path: str | Path, *,
        login_rate_limit_window_seconds: float = 900.0,
        login_rate_limit_max_attempts: int = 5,
        login_rate_limit_row_cap: int = 10000,
    ) -> None:
        self._path = str(config_db_path)
        self._login_rate_limit_window_seconds = login_rate_limit_window_seconds
        self._login_rate_limit_max_attempts = login_rate_limit_max_attempts
        self._login_rate_limit_row_cap = login_rate_limit_row_cap
        # One-time: enable WAL (persists at the DB level), ensure the
        # sessions/tokens tables exist, and ensure this store's OWN
        # uniqueness invariant on owners.email (idx_owners_email). Owners the
        # TABLE is still created by SqliteConfigStore -- that ownership is
        # unchanged -- but set_email's collision translation must not
        # silently depend on SqliteConfigStore having run first (Kleos
        # architect finding MEDIUM): this writer now ensures its own index.
        conn = self._connect()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SESSION_TOKEN_SCHEMA)
            self._ensure_email_uniqueness(conn)
            conn.commit()
        finally:
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path)
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
        return conn

    def _ensure_email_uniqueness(self, conn: sqlite3.Connection) -> None:
        # owners is owned/created by SqliteConfigStore. If THIS store is
        # constructed standalone (no SqliteConfigStore has ever run against
        # this path), the table does not exist yet -- skip silently, there
        # is nothing to index or collide on; SqliteConfigStore's own
        # _migrate() creates the identical idx_owners_email when it runs.
        exists = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'owners'"
        ).fetchone()
        if exists is None:
            return
        # Pre-check BEFORE CREATE UNIQUE INDEX (mirrors SqliteConfigStore.
        # _migrate/_reject_duplicate_identities, Kleos migration checklist
        # #11162): a raw CREATE UNIQUE INDEX on a legacy DB with existing
        # email duplicates raises sqlite3.IntegrityError, which we never let
        # surface un-translated.
        dup_emails = [
            row["email"]
            for row in conn.execute(
                "SELECT email FROM owners WHERE email IS NOT NULL "
                "GROUP BY email HAVING COUNT(*) > 1"
            ).fetchall()
        ]
        if dup_emails:
            raise EmailAlreadyTakenError(
                "cannot enforce owner email uniqueness -- duplicate owner "
                f"emails: {sorted(dup_emails)}. Resolve the duplicate rows "
                "before opening this config.db."
            )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_owners_email "
            "ON owners(email) WHERE email IS NOT NULL"
        )

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

    # -- login rate-limit (roadmap f1048ab8) -------------------------------
    def reserve_login_attempt(
        self, identifier_key: str, *, now: float,
    ) -> float | None:
        if self._login_rate_limit_max_attempts <= 0:
            return None
        conn = self._connect()
        try:
            conn.execute(
                "DELETE FROM login_attempts WHERE window_start <= ?",
                (now - self._login_rate_limit_window_seconds,))
            exists = conn.execute(
                "SELECT 1 FROM login_attempts WHERE identifier_key = ?",
                (identifier_key,)).fetchone()
            if exists is None:
                # The cap bounds STORAGE only -- it never refuses a
                # brand-new identifier. At capacity, evict the oldest
                # tracked row (by window_start) instead.
                count = conn.execute(
                    "SELECT COUNT(*) AS c FROM login_attempts").fetchone()["c"]
                if count >= self._login_rate_limit_row_cap:
                    conn.execute(
                        "DELETE FROM login_attempts WHERE identifier_key = ("
                        "SELECT identifier_key FROM login_attempts "
                        "ORDER BY window_start ASC LIMIT 1)")
            # Single atomic reserve: the increment and the read that
            # decides the outcome happen in the SAME transaction, so
            # concurrent requests for the same identifier_key serialize
            # through SQLite's writer lock rather than all reading the
            # same pre-increment count.
            conn.execute(
                "INSERT INTO login_attempts "
                "(identifier_key, failure_count, window_start) "
                "VALUES (?, 1, ?) "
                "ON CONFLICT(identifier_key) DO UPDATE SET "
                "failure_count = failure_count + 1",
                (identifier_key, now))
            row = conn.execute(
                "SELECT failure_count, window_start FROM login_attempts "
                "WHERE identifier_key = ?", (identifier_key,)).fetchone()
            conn.commit()
        finally:
            conn.close()
        if row["failure_count"] > self._login_rate_limit_max_attempts:
            return self._login_rate_limit_window_seconds - (
                now - row["window_start"])
        return None

    def record_login_success(self, identifier_key: str) -> None:
        if self._login_rate_limit_max_attempts <= 0:
            return
        conn = self._connect()
        try:
            conn.execute(
                "DELETE FROM login_attempts WHERE identifier_key = ?",
                (identifier_key,))
            conn.commit()
        finally:
            conn.close()

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

    # -- self-service profile (WebUI Phase 4b) ------------------------------
    def get_email(self, owner_id: str) -> str | None:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT email FROM owners WHERE id = ?", (owner_id,)
            ).fetchone()
        finally:
            conn.close()
        return row["email"] if row is not None else None

    def set_email(self, owner_id: str, email: str | None) -> None:
        # Format validation happens upstream in AuthService; this method only
        # owns the DB write + the uniqueness-collision translation. A missing
        # owner_id is a silent 0-row UPDATE (no error) -- the caller is always
        # an authenticated principal, so the row exists.
        conn = self._connect()
        try:
            try:
                conn.execute(
                    "UPDATE owners SET email = ? WHERE id = ?",
                    (email, owner_id),
                )
                conn.commit()
            except sqlite3.IntegrityError as exc:
                # idx_owners_email (UNIQUE partial index) collision -- NEVER
                # let the raw IntegrityError surface (Kleos #11162: named
                # error, not a crash).
                conn.rollback()
                raise EmailAlreadyTakenError(
                    f"email already in use: {email!r}") from exc
        finally:
            conn.close()

    def list_tokens(self, owner_id: str, now: str) -> list[TokenInfo]:
        # expires_at > now mirrors resolve_token's expiry filter (Kleos
        # fast-follow item 2): an expired-but-not-revoked token must not
        # appear in the self-service list, even though it is still
        # state='active' in the DB (revocation and expiry are independent).
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT id, created_at, expires_at FROM tokens "
                "WHERE owner_id = ? AND state = 'active' AND expires_at > ? "
                "ORDER BY created_at DESC",
                (owner_id, now),
            ).fetchall()
        finally:
            conn.close()
        return [
            TokenInfo(
                token_id=row["id"],
                created_at=row["created_at"],
                expires_at=row["expires_at"],
            )
            for row in rows
        ]
