"""Phase 3 auth: identity + sessions + bearer + anti-enum + concurrency.

Uses a real Argon2id hasher and REAL temp-file config.db (architect option (a):
connection-per-operation is always exercised; no :memory: special-casing in
prod code). Owners are created via SqliteConfigStore (single-thread CLI write
path); the concurrent verify_* path goes through SqliteAuthStore per-op
connections.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import os
import shutil
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from unittest import mock

from kerdoos.auth.ports import AuthStore, PasswordHasher
from kerdoos.core.app.auth import AuthService
from kerdoos.core.app.services import Principal
from kerdoos.registry.auth_store import Argon2Hasher, SqliteAuthStore
from kerdoos.registry.errors import ConfigError
from kerdoos.registry.sqlite_store import SqliteConfigStore


def _iso(dt: datetime) -> str:
    return dt.isoformat()


class _CountingHasher:
    """Wraps a real hasher, counting Argon2id operations to prove anti-enum:
    every login failure branch must cost EXACTLY one verify/dummy_verify."""

    def __init__(self, real: PasswordHasher) -> None:
        self._real = real
        self.hash_ops = 0

    def hash(self, password: str) -> str:
        return self._real.hash(password)

    def verify(self, password_hash: str, password: str) -> bool:
        self.hash_ops += 1
        return self._real.verify(password_hash, password)

    def dummy_verify(self, password: str) -> None:
        self.hash_ops += 1
        self._real.dummy_verify(password)


class _AuthTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.mkdtemp(prefix="kerdoos-auth-")
        self.addCleanup(shutil.rmtree, self._dir, ignore_errors=True)
        self.db_path = os.path.join(self._dir, "config.db")
        self.config = SqliteConfigStore(self.db_path)
        self.addCleanup(self.config.close)
        self.real_hasher = Argon2Hasher()
        self.store: AuthStore = SqliteAuthStore(self.db_path)
        self.service = AuthService(self.store, self.real_hasher)

    def _add_owner(self, owner_id, name, password, *, role="user", email=None):
        self.config.ensure_owner(
            owner_id, name, role=role, email=email,
            password_hash=self.real_hasher.hash(password))

    def _set_state(self, owner_id: str, state: str) -> None:
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("UPDATE owners SET state = ? WHERE id = ?",
                         (state, owner_id))
            conn.commit()
        finally:
            conn.close()


class HybridIdentityTest(_AuthTestBase):
    def test_login_by_name_or_email_resolves_same_owner(self) -> None:
        self._add_owner("o1", "alice", "s3cret", email="alice@example.com")
        by_name = self.service.authenticate("alice", "s3cret")
        by_email = self.service.authenticate("alice@example.com", "s3cret")
        self.assertIsNotNone(by_name)
        self.assertIsNotNone(by_email)
        self.assertEqual(by_name.owner_id, "o1")
        self.assertEqual(by_email.owner_id, "o1")

    def test_owner_without_email_still_logs_in_by_name(self) -> None:
        self._add_owner("o2", "bob", "hunter2", email=None)
        principal = self.service.authenticate("bob", "hunter2")
        self.assertIsNotNone(principal)
        self.assertEqual(principal.owner_id, "o2")

    def test_role_is_server_resolved_from_owners_not_input(self) -> None:
        # The caller supplies only identifier + password; role comes from the
        # DB. An admin owner authenticates as admin; a user cannot elevate.
        self._add_owner("adm", "root", "pw", role="admin")
        self._add_owner("usr", "joe", "pw", role="user")
        self.assertEqual(self.service.authenticate("root", "pw").role, "admin")
        self.assertEqual(self.service.authenticate("joe", "pw").role, "user")


class AntiEnumerationTest(_AuthTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.counting = _CountingHasher(self.real_hasher)
        self.service = AuthService(self.store, self.counting)
        self._add_owner("o1", "alice", "s3cret")
        # An owner with NO password (password_hash NULL).
        self.config.ensure_owner("o2", "nopass", role="user",
                                 password_hash=None)

    def test_three_failure_paths_same_cost_and_uniform_reject(self) -> None:
        # 1. unknown identifier
        self.counting.hash_ops = 0
        self.assertIsNone(self.service.authenticate("ghost", "whatever"))
        self.assertEqual(self.counting.hash_ops, 1)
        # 2. known owner, wrong password
        self.counting.hash_ops = 0
        self.assertIsNone(self.service.authenticate("alice", "wrong"))
        self.assertEqual(self.counting.hash_ops, 1)
        # 3. known owner with NULL password_hash
        self.counting.hash_ops = 0
        self.assertIsNone(self.service.authenticate("nopass", "whatever"))
        self.assertEqual(self.counting.hash_ops, 1)

    def test_success_also_one_verify(self) -> None:
        self.counting.hash_ops = 0
        self.assertIsNotNone(self.service.authenticate("alice", "s3cret"))
        self.assertEqual(self.counting.hash_ops, 1)


class OwnerUniquenessTest(_AuthTestBase):
    def test_duplicate_name_rejected_as_config_error(self) -> None:
        self._add_owner("o1", "alice", "pw")
        with self.assertRaises(ConfigError):
            self._add_owner("o2", "alice", "pw")   # same name

    def test_duplicate_email_rejected_as_config_error(self) -> None:
        self._add_owner("o1", "alice", "pw", email="a@x.com")
        with self.assertRaises(ConfigError):
            self._add_owner("o2", "bob", "pw", email="a@x.com")   # same email

    def test_multiple_owners_without_email_ok(self) -> None:
        # Partial unique index -> many owners may have NULL email (WebUI-only).
        self.config.ensure_owner("o1", "alice", email=None)
        self.config.ensure_owner("o2", "bob", email=None)
        reg_names = {
            r[0] for r in sqlite3.connect(self.db_path).execute(
                "SELECT name FROM owners").fetchall()
        }
        self.assertIn("alice", reg_names)
        self.assertIn("bob", reg_names)


class SessionHashStorageTest(_AuthTestBase):
    def test_db_stores_hash_not_plaintext_session_id(self) -> None:
        self._add_owner("o1", "alice", "pw")
        session_id = self.service.create_session(Principal("o1", "user"))
        conn = sqlite3.connect(self.db_path)
        try:
            rows = conn.execute("SELECT session_hash FROM sessions").fetchall()
        finally:
            conn.close()
        self.assertEqual(len(rows), 1)
        stored = rows[0][0]
        # The plaintext session id is NEVER in the DB; only its sha256.
        self.assertNotEqual(stored, session_id)
        self.assertEqual(
            stored, hashlib.sha256(session_id.encode("utf-8")).hexdigest())
        # And the plaintext still verifies (resolved by hash).
        self.assertIsNotNone(self.service.verify_session(session_id))


class SessionTest(_AuthTestBase):
    def test_create_verify_revoke_session(self) -> None:
        self._add_owner("o1", "alice", "pw", role="admin")
        principal = Principal(owner_id="o1", role="admin")
        sid = self.service.create_session(principal)
        resolved = self.service.verify_session(sid)
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved.owner_id, "o1")
        self.assertEqual(resolved.role, "admin")   # role server-resolved
        self.service.revoke_session(principal, sid)
        self.assertIsNone(self.service.verify_session(sid))

    def test_disabled_owner_session_cut_even_with_valid_ttl(self) -> None:
        self._add_owner("o1", "alice", "pw")
        sid = self.service.create_session(Principal("o1", "user"))
        self.assertIsNotNone(self.service.verify_session(sid))   # active -> ok
        self._set_state("o1", "disabled")
        # TTL still in the future, but the inline state filter cuts access.
        self.assertIsNone(self.service.verify_session(sid))

    def test_expired_session_rejected(self) -> None:
        self._add_owner("o1", "alice", "pw")
        # Mint far enough in the past that created_at + session_ttl < now.
        past = datetime.now(timezone.utc) - timedelta(days=365)
        svc = AuthService(self.store, self.real_hasher, clock=lambda: past)
        sid = svc.create_session(Principal("o1", "user"))   # expires in the past
        # Verify with the real (now) clock -> expired.
        self.assertIsNone(self.service.verify_session(sid))


class TokenAuthZTest(_AuthTestBase):
    def test_create_token_mints_for_acting_principal_only(self) -> None:
        self._add_owner("admin", "root", "pw", role="admin")
        self._add_owner("victim", "vic", "pw", role="user")
        admin = Principal("admin", "admin")
        issued = self.service.create_token(admin)
        resolved = self.service.verify_bearer(issued.token)
        self.assertIsNotNone(resolved)
        # The minted token belongs to the admin, NEVER to another owner -- there
        # is no target-owner parameter on create_token to abuse.
        self.assertEqual(resolved.owner_id, "admin")

    def test_verify_bearer_role_server_resolved(self) -> None:
        self._add_owner("admin", "root", "pw", role="admin")
        issued = self.service.create_token(Principal("admin", "admin"))
        self.assertEqual(self.service.verify_bearer(issued.token).role, "admin")

    def test_disabled_owner_token_cut_even_with_valid_ttl(self) -> None:
        self._add_owner("o1", "alice", "pw")
        issued = self.service.create_token(Principal("o1", "user"))
        self.assertIsNotNone(self.service.verify_bearer(issued.token))
        self._set_state("o1", "disabled")
        self.assertIsNone(self.service.verify_bearer(issued.token))

    def test_revoke_token_self(self) -> None:
        self._add_owner("o1", "alice", "pw")
        p = Principal("o1", "user")
        issued = self.service.create_token(p)
        self.service.revoke_token(p, issued.token_id)
        self.assertIsNone(self.service.verify_bearer(issued.token))

    def test_revoke_all_admin_only_for_other_target(self) -> None:
        self._add_owner("admin", "root", "pw", role="admin")
        self._add_owner("victim", "vic", "pw", role="user")
        # A regular user cannot revoke another owner's access.
        user = Principal("victim", "user")
        with self.assertRaises(PermissionError):
            self.service.revoke_all(user, "admin")
        # Self-revoke is allowed for a user.
        issued = self.service.create_token(user)
        self.service.revoke_all(user, "victim")
        self.assertIsNone(self.service.verify_bearer(issued.token))
        # An admin can revoke any target.
        admin = Principal("admin", "admin")
        victim_tok = self.service.create_token(Principal("victim", "user"))
        self.service.revoke_all(admin, "victim")
        self.assertIsNone(self.service.verify_bearer(victim_tok.token))


class ConcurrencyTest(_AuthTestBase):
    def test_verify_paths_concurrent_no_programming_error(self) -> None:
        # Proves the per-op-connection invariant (architect FD3): verify_* hit
        # from many OS threads must not raise sqlite3.ProgrammingError (a shared
        # check_same_thread=True connection WOULD) and must not serialize on a
        # shared lock. BITES if verify_* is ever re-routed onto the single
        # SqliteConfigStore connection.
        self._add_owner("o1", "alice", "pw")
        p = Principal("o1", "user")
        token = self.service.create_token(p).token
        sid = self.service.create_session(p)

        errors: list[Exception] = []
        ok = 0
        lock = __import__("threading").Lock()

        def _hammer() -> None:
            nonlocal ok
            try:
                for _ in range(20):
                    assert self.service.verify_bearer(token) is not None
                    assert self.service.verify_session(sid) is not None
                    assert self.store.lookup_active_credentials("alice") is not None
                with lock:
                    ok += 1
            except Exception as exc:  # noqa: BLE001 -- capture for assertion
                with lock:
                    errors.append(exc)

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(_hammer) for _ in range(8)]
            for f in futures:
                f.result(timeout=30)

        self.assertEqual(errors, [])
        self.assertEqual(ok, 8)


class CliUserAddTest(_AuthTestBase):
    def test_user_add_hybrid_password_via_stdin_never_arg(self) -> None:
        from kerdoos.interfaces.cli import main as cli

        args = cli.build_parser_cli().parse_args([
            "user", "add", "--name", "carol", "--email", "carol@example.com",
            "--admin", "--config-db", self.db_path])
        buf = io.StringIO()
        # Password comes from stdin (non-tty), never as a CLI arg.
        with mock.patch("sys.stdin", io.StringIO("topsecret\n")):
            with contextlib.redirect_stdout(buf):
                rc = args.func(args)
        self.assertEqual(rc, 0)

        # The created owner authenticates by name AND email, as admin, with the
        # password that was only ever supplied on stdin.
        svc = AuthService(SqliteAuthStore(self.db_path), self.real_hasher)
        by_name = svc.authenticate("carol", "topsecret")
        self.assertIsNotNone(by_name)
        self.assertEqual(by_name.role, "admin")
        self.assertIsNotNone(svc.authenticate("carol@example.com", "topsecret"))
        # Wrong password is rejected (password was really hashed, not stored raw).
        self.assertIsNone(svc.authenticate("carol", "wrong"))


class MigrationTest(unittest.TestCase):
    def test_pre_phase3_db_migrates_additively(self) -> None:
        # Simulate a pre-Phase-3 config.db: owners WITHOUT password_hash/created_at.
        d = tempfile.mkdtemp(prefix="kerdoos-mig-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        path = os.path.join(d, "config.db")
        conn = sqlite3.connect(path)
        conn.executescript(
            "CREATE TABLE owners (id TEXT PRIMARY KEY, name TEXT NOT NULL, "
            "email TEXT, role TEXT NOT NULL DEFAULT 'user', "
            "state TEXT NOT NULL DEFAULT 'active');"
            "INSERT INTO owners (id, name, role) VALUES ('legacy', 'old', 'admin');"
        )
        conn.commit()
        conn.close()

        # Opening with the Phase 3 store must migrate additively, preserving the
        # legacy owner, and add the new columns.
        store = SqliteConfigStore(path)
        try:
            cols = {row["name"] for row in
                    store._conn.execute("PRAGMA table_info(owners)").fetchall()}
            self.assertIn("password_hash", cols)
            self.assertIn("created_at", cols)
            row = store._conn.execute(
                "SELECT name, role FROM owners WHERE id = 'legacy'").fetchone()
            self.assertEqual(row["name"], "old")
            self.assertEqual(row["role"], "admin")
            version = store._conn.execute("PRAGMA user_version").fetchone()[0]
            self.assertEqual(version, 3)
        finally:
            store.close()

    def test_legacy_duplicate_name_raises_named_config_error(self) -> None:
        # A pre-uniqueness config.db with duplicate names must fail with a clear
        # ConfigError (listing the collision), NOT a raw IntegrityError that
        # leaves the DB unopenable (gate C1).
        d = tempfile.mkdtemp(prefix="kerdoos-mig-dup-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        path = os.path.join(d, "config.db")
        conn = sqlite3.connect(path)
        conn.executescript(
            "CREATE TABLE owners (id TEXT PRIMARY KEY, name TEXT NOT NULL, "
            "email TEXT, role TEXT NOT NULL DEFAULT 'user', "
            "state TEXT NOT NULL DEFAULT 'active');"
            "INSERT INTO owners (id, name) VALUES ('a', 'dup');"
            "INSERT INTO owners (id, name) VALUES ('b', 'dup');"
        )
        conn.commit()
        conn.close()
        with self.assertRaises(ConfigError) as ctx:
            SqliteConfigStore(path)
        self.assertIn("dup", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
