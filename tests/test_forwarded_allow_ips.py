"""Proxy-header trust of the Docker image's uvicorn launch.

The Dockerfile CMD is executed for real by sh, with a stub `uvicorn` on PATH
that prints its argv. That argv is then fed to uvicorn's own CLI parser and
Config wiring, which resolve the client address of a request carrying a
forged X-Forwarded-For.
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_DOCKERFILE = Path(__file__).resolve().parents[1] / "Dockerfile"
_SH = shutil.which("sh")
_HAS_UVICORN = importlib.util.find_spec("uvicorn") is not None
_LAUNCH_ENV_VARS = (
    "KERDOOS_FORWARDED_ALLOW_IPS", "FORWARDED_ALLOW_IPS", "KERDOOS_WORKERS")

_PROXY = "192.0.2.10"
_FORGED = "203.0.113.7"


def _cmd_script() -> str:
    lines = _DOCKERFILE.read_text(encoding="utf-8").splitlines()
    cmd_starts = [i for i, line in enumerate(lines) if line.startswith("CMD ")]
    assert len(cmd_starts) == 1, f"expected one CMD, found {len(cmd_starts)}"
    parts = []
    for line in lines[cmd_starts[0]:]:
        stripped = line.rstrip()
        continued = stripped.endswith("\\")
        parts.append(stripped[:-1] if continued else stripped)
        if not continued:
            break
    return " ".join(parts)[len("CMD "):]


def _launch_env(overrides: dict[str, str]) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in _LAUNCH_ENV_VARS}
    env.update(overrides)
    return env


def _launch_argv(overrides: dict[str, str]) -> list[str]:
    with tempfile.TemporaryDirectory() as stub_dir:
        stub = Path(stub_dir) / "uvicorn"
        stub.write_text(
            '#!/bin/sh\nprintf "%s\\n" "$@"\n', encoding="utf-8", newline="\n")
        stub.chmod(0o755)
        env = _launch_env(overrides)
        env["PATH"] = stub_dir + os.pathsep + env.get("PATH", "")
        result = subprocess.run(
            [_SH, "-c", _cmd_script()], env=env, capture_output=True,
            text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    return result.stdout.splitlines()


def _resolved_client(
    overrides: dict[str, str], peer: str, x_forwarded_for: str,
) -> str:
    from uvicorn.config import Config
    from uvicorn.main import main as uvicorn_cli

    params = uvicorn_cli.make_context(
        "uvicorn", _launch_argv(overrides)).params
    seen: dict[str, str] = {}

    async def app(scope, receive, send) -> None:
        seen["client"] = scope["client"][0]

    with mock.patch.dict(os.environ, _launch_env(overrides), clear=True):
        config = Config(
            app, log_config=None,
            proxy_headers=params["proxy_headers"],
            forwarded_allow_ips=params["forwarded_allow_ips"])
        config.load()

    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": "GET", "scheme": "http", "path": "/", "raw_path": b"/",
        "query_string": b"", "root_path": "", "server": ("0.0.0.0", 8000),
        "client": (peer, 40000),
        "headers": [(b"x-forwarded-for", x_forwarded_for.encode("latin-1"))],
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message) -> None:
        return None

    asyncio.run(config.loaded_app(scope, receive, send))
    return seen["client"]


@unittest.skipUnless(_SH, "sh not available")
class DockerCmdProxyArgsTest(unittest.TestCase):

    def test_unset_trust_list_disables_proxy_headers(self) -> None:
        argv = _launch_argv({})
        self.assertIn("--no-proxy-headers", argv)
        self.assertNotIn("--forwarded-allow-ips", argv)

    def test_empty_trust_list_disables_proxy_headers(self) -> None:
        argv = _launch_argv({"KERDOOS_FORWARDED_ALLOW_IPS": ""})
        self.assertIn("--no-proxy-headers", argv)
        self.assertNotIn("--forwarded-allow-ips", argv)

    def test_trust_list_is_passed_verbatim_to_uvicorn(self) -> None:
        value = f"{_PROXY}, 198.51.100.0/24"
        argv = _launch_argv({"KERDOOS_FORWARDED_ALLOW_IPS": value})
        index = argv.index("--forwarded-allow-ips")
        self.assertEqual(argv[index + 1], value)
        self.assertNotIn("--no-proxy-headers", argv)

    def test_worker_count_still_reaches_uvicorn(self) -> None:
        argv = _launch_argv({
            "KERDOOS_WORKERS": "4", "KERDOOS_FORWARDED_ALLOW_IPS": _PROXY})
        index = argv.index("--workers")
        self.assertEqual(argv[index + 1], "4")


@unittest.skipUnless(_SH and _HAS_UVICORN, "sh or uvicorn not available")
class DockerCmdClientAddressTest(unittest.TestCase):

    def test_forged_header_from_loopback_peer_ignored_when_unset(self) -> None:
        client = _resolved_client({}, "127.0.0.1", _FORGED)
        self.assertEqual(
            client, "127.0.0.1",
            "uvicorn's implicit 127.0.0.1 trust must not survive the launch")

    def test_stray_uvicorn_env_does_not_reopen_trust_when_unset(self) -> None:
        client = _resolved_client({"FORWARDED_ALLOW_IPS": "*"}, _PROXY, _FORGED)
        self.assertEqual(client, _PROXY)

    def test_trusted_proxy_yields_address_it_appended(self) -> None:
        client = _resolved_client(
            {"KERDOOS_FORWARDED_ALLOW_IPS": _PROXY}, _PROXY,
            f"{_FORGED}, 198.51.100.4")
        self.assertEqual(
            client, "198.51.100.4",
            "the entry appended by the trusted proxy wins, never the leftmost")

    def test_explicit_trust_list_overrides_stray_uvicorn_env(self) -> None:
        client = _resolved_client(
            {"KERDOOS_FORWARDED_ALLOW_IPS": _PROXY, "FORWARDED_ALLOW_IPS": "*"},
            "198.51.100.200", _FORGED)
        self.assertEqual(client, "198.51.100.200")

    def test_whitespace_only_trust_list_trusts_nothing(self) -> None:
        client = _resolved_client(
            {"KERDOOS_FORWARDED_ALLOW_IPS": "   "}, _PROXY, _FORGED)
        self.assertEqual(client, _PROXY)


if __name__ == "__main__":
    unittest.main()
