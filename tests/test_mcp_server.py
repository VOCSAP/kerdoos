"""MCP server mounted at /mcp: the bearer gate, the Host allowlist and the
boot refusals, exercised over HTTP through TestClient(create_app()) with the
SDK's own middleware in the request path (ADR 0005, tranche T0)."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import shutil
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock
from urllib.parse import urlsplit

from fastapi.testclient import TestClient

from kerdoos.core.app.auth import AuthService
from kerdoos.core.app.services import Principal
from kerdoos.interfaces.web.app import create_app
from kerdoos.registry.auth_store import Argon2Hasher, SqliteAuthStore
from kerdoos.registry.sqlite_store import SqliteConfigStore

_PROTOCOL_VERSION = "2025-11-25"
_METADATA_PATH = "/mcp/.well-known/oauth-protected-resource/mcp"
_OWNER_ID = "owner-5f1c9e"
_OWNER_NAME = "alice-mcp"
_MCP_ENV_VARS = (
    "KERDOOS_MCP_ENABLED", "KERDOOS_PUBLIC_URL", "KERDOOS_MCP_ALLOWED_HOSTS")


def _base_env(directory: str) -> dict[str, str]:
    return {
        "KERDOOS_SESSION_SECRET": "test-session-secret-padded-to-32chars",
        "KERDOOS_CONFIG_DB": os.path.join(directory, "config.db"),
        "KERDOOS_STATE_DB": os.path.join(directory, "state.db"),
        "KERDOOS_COOKIE_SECURE": "false",
    }


def _patch_env(test: unittest.TestCase, env: dict[str, str]) -> None:
    patcher = mock.patch.dict(os.environ, env)
    patcher.start()
    test.addCleanup(patcher.stop)
    for var in _MCP_ENV_VARS:
        if var not in env:
            os.environ.pop(var, None)


def _initialize() -> dict:
    return {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": _PROTOCOL_VERSION, "capabilities": {},
            "clientInfo": {"name": "kerdoos-tests", "version": "0"},
        },
    }


def _jsonrpc_payload(response) -> dict:
    if response.headers.get("content-type", "").startswith("text/event-stream"):
        data = [line[len("data:"):].strip()
                for line in response.text.splitlines()
                if line.startswith("data:")]
        return json.loads(data[-1])
    return response.json()


def _advertised_metadata_url(rejected_response) -> str:
    challenge = rejected_response.headers["www-authenticate"]
    marker = 'resource_metadata="'
    start = challenge.index(marker) + len(marker)
    return challenge[start:challenge.index('"', start)]


def _sha256(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class _RecordingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


class _McpTestBase(unittest.TestCase):
    extra_env: dict[str, str] = {}

    def setUp(self) -> None:
        self._dir = tempfile.mkdtemp(prefix="kerdoos-mcp-")
        self.addCleanup(shutil.rmtree, self._dir, ignore_errors=True)
        env = _base_env(self._dir)
        env.update({
            "KERDOOS_MCP_ENABLED": "true",
            "KERDOOS_PUBLIC_URL": "http://testserver",
        })
        env.update(self.extra_env)
        _patch_env(self, env)
        self.config_db = env["KERDOOS_CONFIG_DB"]
        SqliteConfigStore(self.config_db).close()
        self.hasher = Argon2Hasher()
        self.auth = AuthService(SqliteAuthStore(self.config_db), self.hasher)
        self.client = TestClient(create_app())
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)

    def _add_owner(self, owner_id: str, name: str, role: str = "user") -> None:
        store = SqliteConfigStore(self.config_db)
        try:
            store.ensure_owner(owner_id, name, role=role, password_hash=None)
        finally:
            store.close()

    def _set_state(self, owner_id: str, state: str) -> None:
        conn = sqlite3.connect(self.config_db)
        try:
            conn.execute(
                "UPDATE owners SET state = ? WHERE id = ?", (state, owner_id))
            conn.commit()
        finally:
            conn.close()

    def _post(self, body: dict, *, authorization: str | None = None,
              headers: dict[str, str] | None = None):
        request_headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        if authorization is not None:
            request_headers["Authorization"] = authorization
        request_headers.update(headers or {})
        return self.client.post(
            "/mcp/", content=json.dumps(body), headers=request_headers)

    def _whoami(self, authorization: str) -> list:
        init = self._post(_initialize(), authorization=authorization)
        session = {"mcp-protocol-version": _PROTOCOL_VERSION}
        if "mcp-session-id" in init.headers:
            session["mcp-session-id"] = init.headers["mcp-session-id"]
        initialized = self._post(
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            authorization=authorization, headers=session)
        call = self._post(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "whoami", "arguments": {}}},
            authorization=authorization, headers=session)
        return [init, initialized, call]

    def _assert_advertised_metadata_is_served(self) -> None:
        rejected = self._post(_initialize())
        self.assertEqual(rejected.status_code, 401)
        advertised = urlsplit(_advertised_metadata_url(rejected))
        self.assertEqual(advertised.netloc, "testserver")
        served = self.client.get(advertised.path)
        self.assertEqual(
            served.status_code, 200,
            f"{advertised.path} is advertised by the 401 but not served")
        in_mount = self.client.get(f"/mcp{advertised.path}")
        self.assertEqual(in_mount.status_code, 200, in_mount.text)
        self.assertEqual(served.json(), in_mount.json())
        self.assertEqual(
            served.json()["resource"],
            os.environ["KERDOOS_PUBLIC_URL"] + "/mcp")


class BearerGateTest(_McpTestBase):

    def test_every_rejection_cause_gets_a_byte_identical_401(self) -> None:
        principal = Principal(_OWNER_ID, "user")
        self._add_owner(_OWNER_ID, _OWNER_NAME)
        self._add_owner("owner-disabled", "bob-mcp")
        past = datetime.now(timezone.utc) - timedelta(days=365)
        expired = AuthService(
            SqliteAuthStore(self.config_db), self.hasher, clock=lambda: past,
        ).create_token(principal).token
        revoked = self.auth.create_token(principal)
        self.auth.revoke_token(principal, revoked.token_id)
        disabled = self.auth.create_token(
            Principal("owner-disabled", "user")).token
        self._set_state("owner-disabled", "disabled")

        causes = {
            "no header": None,
            "unknown token": f"Bearer {secrets.token_urlsafe(32)}",
            "expired token": f"Bearer {expired}",
            "revoked token": f"Bearer {revoked.token}",
            "disabled owner": f"Bearer {disabled}",
        }
        observed = {}
        for cause, authorization in causes.items():
            response = self._post(_initialize(), authorization=authorization)
            headers = sorted(
                (name.lower(), value) for name, value in response.headers.items()
                if name.lower() != "date")
            observed[cause] = (response.status_code, response.content, headers)

        for cause, value in observed.items():
            with self.subTest(cause=cause):
                self.assertEqual(value[0], 401)
                self.assertEqual(value, observed["no header"])

    def test_scheme_is_accepted_in_any_case(self) -> None:
        self._add_owner(_OWNER_ID, _OWNER_NAME)
        token = self.auth.create_token(Principal(_OWNER_ID, "user")).token
        for scheme in ("BEARER", "bearer"):
            with self.subTest(scheme=scheme):
                init, _, call = self._whoami(f"{scheme} {token}")
                self.assertEqual(init.status_code, 200, init.text)
                self.assertEqual(call.status_code, 200, call.text)
                self.assertEqual(
                    _jsonrpc_payload(call)["result"]["structuredContent"],
                    {"role": "user"})

    def test_whoami_returns_the_role_and_never_the_owner_identity(self) -> None:
        self._add_owner(_OWNER_ID, _OWNER_NAME, role="admin")
        token = self.auth.create_token(Principal(_OWNER_ID, "admin")).token
        responses = self._whoami(f"Bearer {token}")
        result = _jsonrpc_payload(responses[-1])["result"]
        self.assertFalse(result.get("isError"), result)
        self.assertEqual(result["structuredContent"], {"role": "admin"})
        for response in responses:
            self.assertNotIn(_OWNER_ID, response.text)
            self.assertNotIn(_OWNER_NAME, response.text)
        self.assertEqual(self.client.get("/health").status_code, 200)

    def test_token_hash_never_reaches_a_response_or_a_log(self) -> None:
        principal = Principal(_OWNER_ID, "user")
        self._add_owner(_OWNER_ID, _OWNER_NAME)
        valid = self.auth.create_token(principal).token
        revoked = self.auth.create_token(principal)
        self.auth.revoke_token(principal, revoked.token_id)

        handler = _RecordingHandler()
        root = logging.getLogger()
        previous_level = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        try:
            responses = self._whoami(f"Bearer {valid}")
            responses.append(
                self._post(_initialize(), authorization=f"Bearer {revoked.token}"))
        finally:
            root.removeHandler(handler)
            root.setLevel(previous_level)

        self.assertEqual(
            _jsonrpc_payload(responses[2])["result"]["structuredContent"],
            {"role": "user"}, "the valid token must reach the tool")
        self.assertEqual(responses[3].status_code, 401)
        responses.append(self.client.get(_METADATA_PATH))

        exposed = [response.text + repr(dict(response.headers))
                   for response in responses]
        for secret_value in (_sha256(valid), _sha256(revoked.token)):
            for text in exposed:
                self.assertNotIn(secret_value, text)
            for message in handler.messages:
                self.assertNotIn(secret_value, message)

    def test_metadata_url_advertised_by_the_401_is_served(self) -> None:
        self._assert_advertised_metadata_is_served()

    def test_unauthenticated_resource_metadata_names_no_owner(self) -> None:
        self._add_owner(_OWNER_ID, _OWNER_NAME)
        metadata = self.client.get(_METADATA_PATH)
        self.assertEqual(metadata.status_code, 200, metadata.text)
        self.assertEqual(
            set(metadata.json()),
            {"resource", "authorization_servers", "bearer_methods_supported"})
        self.assertNotIn(_OWNER_ID, metadata.text)
        self.assertNotIn(_OWNER_NAME, metadata.text)


class HostAllowlistTest(_McpTestBase):

    def test_host_outside_the_allowlist_is_misdirected(self) -> None:
        self._add_owner(_OWNER_ID, _OWNER_NAME)
        token = self.auth.create_token(Principal(_OWNER_ID, "user")).token
        response = self._post(
            _initialize(), authorization=f"Bearer {token}",
            headers={"Host": "attacker.example"})
        self.assertEqual(response.status_code, 421)


class PublicUrlWithPathTest(_McpTestBase):
    extra_env = {
        "KERDOOS_PUBLIC_URL": "http://testserver/kerdoos",
        "KERDOOS_MCP_ALLOWED_HOSTS": "testserver",
    }

    def test_metadata_url_advertised_by_the_401_is_served(self) -> None:
        self._assert_advertised_metadata_is_served()


class ExtraAllowedHostTest(_McpTestBase):
    extra_env = {"KERDOOS_MCP_ALLOWED_HOSTS": "kerdoos.lan, 192.0.2.5:8000"}

    def test_listed_host_is_accepted_in_addition_to_the_public_url(self) -> None:
        self._add_owner(_OWNER_ID, _OWNER_NAME)
        token = self.auth.create_token(Principal(_OWNER_ID, "user")).token
        for host in ("kerdoos.lan", "192.0.2.5:8000", "testserver"):
            with self.subTest(host=host):
                response = self._post(
                    _initialize(), authorization=f"Bearer {token}",
                    headers={"Host": host})
                self.assertEqual(response.status_code, 200, response.text)


class McpBootTest(unittest.TestCase):

    def setUp(self) -> None:
        self._dir = tempfile.mkdtemp(prefix="kerdoos-mcp-boot-")
        self.addCleanup(shutil.rmtree, self._dir, ignore_errors=True)

    def test_enabled_without_public_url_refuses_to_start(self) -> None:
        env = _base_env(self._dir)
        env["KERDOOS_MCP_ENABLED"] = "true"
        _patch_env(self, env)
        with self.assertRaisesRegex(RuntimeError, "KERDOOS_PUBLIC_URL"):
            create_app()

    def test_wildcard_allowed_host_refuses_to_start(self) -> None:
        for value in ("*", "kerdoos.lan, *", "kerdoos.lan:*"):
            with self.subTest(value=value):
                env = _base_env(self._dir)
                env.update({
                    "KERDOOS_MCP_ENABLED": "true",
                    "KERDOOS_PUBLIC_URL": "http://kerdoos.lan",
                    "KERDOOS_MCP_ALLOWED_HOSTS": value,
                })
                with mock.patch.dict(os.environ, env):
                    with self.assertRaisesRegex(
                            RuntimeError, "KERDOOS_MCP_ALLOWED_HOSTS"):
                        create_app()

    def test_enabling_mcp_leaves_the_root_logger_untouched(self) -> None:
        env = _base_env(self._dir)
        env.update({
            "KERDOOS_MCP_ENABLED": "true",
            "KERDOOS_PUBLIC_URL": "http://testserver",
        })
        _patch_env(self, env)
        root = logging.getLogger()
        saved_handlers, saved_level = root.handlers[:], root.level
        # An empty root is the only state in which basicConfig acts.
        root.handlers[:] = []
        root.setLevel(logging.WARNING)
        try:
            create_app()
            handlers_after, level_after = root.handlers[:], root.level
        finally:
            root.handlers[:] = saved_handlers
            root.setLevel(saved_level)
        self.assertEqual(handlers_after, [])
        self.assertEqual(logging.getLevelName(level_after), "WARNING")

    def test_disabled_by_default_mounts_nothing(self) -> None:
        _patch_env(self, _base_env(self._dir))
        app = create_app()
        self.assertNotIn("/mcp", [getattr(route, "path", None) for route in app.routes])
        with TestClient(app) as client:
            response = client.post("/mcp/", json=_initialize())
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
