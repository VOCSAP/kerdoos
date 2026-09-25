"""Real BrowserFetcher WebRTC egress proof.

Build the required image from the repository root:
    docker build --target autonomous-test -t kerdoos-t4-test:local .
"""

from __future__ import annotations

import functools
import importlib.util
import os
import socket
import ssl
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from autolycos import safety
from autolycos.adapters import browser
from autolycos.egress_proxy import PinningProxy
from autolycos.safety import DomainPolicy
from tests.image.webrtc_image_support import (
    NssTrustedCertificate,
    UdpCapture,
    lan_ip,
    runtime_certificate_tools_available,
    webrtc_page,
)

_HAS_PATCHRIGHT = importlib.util.find_spec("patchright") is not None
_HAS_POSIX_SHELL = os.name == "posix" and Path("/bin/sh").is_file()
_WEBRTC_POLICY = "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"


class _NoopStealth:
    def apply_stealth_sync(self, page) -> None:  # noqa: ANN001
        pass


class BrowserWebRtcEgressImageTest(unittest.TestCase):
    def setUp(self) -> None:
        if (
            _HAS_PATCHRIGHT
            and _HAS_POSIX_SHELL
            and runtime_certificate_tools_available()
        ):
            self._certificate = NssTrustedCertificate()
            self.addCleanup(self._certificate.cleanup)
            return
        if os.environ.get("KERDOOS_REQUIRE_IMAGE_TESTS") == "1":
            self.fail(
                "KERDOOS_REQUIRE_IMAGE_TESTS=1 but patchright, a POSIX shell, "
                "openssl, or NSS certutil is unavailable"
            )
        self.skipTest(
            "needs patchright, a POSIX shell, openssl, and NSS certutil "
            "(autonomous image)"
        )

    def test_fetch_blocks_unproxied_webrtc_udp_and_keeps_status(self) -> None:
        local_ip = lan_ip()
        page = webrtc_page(local_ip)

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.path == "/hold":
                    time.sleep(2.0)
                    body = b"ok"
                else:
                    body = page
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args) -> None:  # noqa: ANN002
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(
            self._certificate.certificate, self._certificate.private_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)

        capture = UdpCapture()
        capture.start()
        self._assert_unprotected_chromium_hits_canary(capture, server.server_port)
        capture.clear()

        from patchright.sync_api import BrowserType
        import psutil

        observed_args: list[str] = []
        original_launch = BrowserType.launch

        def capture_launch(browser_type, **kwargs):  # noqa: ANN001, ANN003
            launched = original_launch(browser_type, **kwargs)
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline and not observed_args:
                for process in psutil.Process().children(recursive=True):
                    try:
                        command = process.cmdline()
                    except psutil.Error:
                        continue
                    if "--autolycos-launch-id=webrtc-proof" in command:
                        observed_args.extend(command)
                        break
                time.sleep(0.05)
            return launched

        def safe_addrinfo(_host, port, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                     "", ("104.18.0.1", port))]

        def dial(_ip: str, _port: int) -> socket.socket:
            connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connection.connect(("127.0.0.1", server.server_port))
            return connection

        with mock.patch.object(browser, "PinningProxy", functools.partial(
                PinningProxy, dialer=dial)), \
             mock.patch.object(browser, "_load_stealth", return_value=_NoopStealth), \
             mock.patch.object(browser.uuid, "uuid4", return_value=SimpleNamespace(
                 hex="webrtc-proof")), \
             mock.patch.object(BrowserType, "launch", capture_launch), \
             mock.patch.object(safety.socket, "getaddrinfo", safe_addrinfo):
            result = browser.BrowserFetcher(
                DomainPolicy(frozenset({"shop.test"}))).fetch(
                    "https://shop.test/webrtc")

        time.sleep(0.5)
        self.assertEqual(result.status, 200)
        self.assertIn("webrtc-page-loaded", result.html)
        self.assertEqual(capture.events(), [], "WebRTC emitted direct UDP")
        self.assertIn(_WEBRTC_POLICY, observed_args)

    def _assert_unprotected_chromium_hits_canary(
            self, capture: UdpCapture, origin_port: int) -> None:
        from patchright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            chromium = playwright.chromium.launch(
                headless=True,
                args=["--host-resolver-rules="
                      f"MAP shop.test:443 127.0.0.1:{origin_port}"],
            )
            try:
                page = chromium.new_page()
                page.goto("https://shop.test/webrtc", wait_until="networkidle",
                          timeout=30_000)
            finally:
                chromium.close()
        time.sleep(0.5)
        self.assertTrue(capture.events(), "unprotected Chromium missed the UDP canary")


if __name__ == "__main__":
    unittest.main()
