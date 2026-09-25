"""Real BrowserFetcher WebRTC egress proof.

Build the required image from the repository root:
    docker build --target autonomous-test -t kerdoos-t4-test:local .
"""

from __future__ import annotations

import functools
import importlib.util
import os
import shutil
import socket
import ssl
import subprocess
import struct
import tempfile
import threading
import time
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from autolycos import safety
from autolycos.adapters import browser
from autolycos.egress_proxy import PinningProxy
from autolycos.safety import DomainPolicy

_HAS_PATCHRIGHT = importlib.util.find_spec("patchright") is not None
_PRIVATE_PORTS = frozenset({3478, 3479, 3480, 3481, 3482, 3483})
_WEBRTC_POLICY = "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"


class _NoopStealth:
    def apply_stealth_sync(self, page) -> None:  # noqa: ANN001
        pass


def _runtime_certificate_tools_available() -> bool:
    return all(shutil.which(tool) for tool in ("openssl", "certutil"))


class _NssTrustedCertificate:
    def __init__(self) -> None:
        self._directory = tempfile.TemporaryDirectory(prefix="kerdoos-webrtc-")
        directory = Path(self._directory.name)
        ca_certificate = directory / "ca.crt"
        ca_key = directory / "ca.key"
        leaf_request = directory / "leaf.csr"
        self.certificate = directory / "leaf.crt"
        self.private_key = directory / "leaf.key"
        extensions = directory / "leaf.ext"
        extensions.write_text(
            "subjectAltName=DNS:shop.test\n"
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n",
            encoding="ascii",
        )
        self._run(
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "1", "-subj", "/CN=Kerdoos Test CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-keyout", str(ca_key), "-out", str(ca_certificate),
        )
        self._run(
            "openssl", "req", "-newkey", "rsa:2048", "-nodes",
            "-subj", "/CN=shop.test", "-keyout", str(self.private_key),
            "-out", str(leaf_request),
        )
        self._run(
            "openssl", "x509", "-req", "-in", str(leaf_request),
            "-CA", str(ca_certificate), "-CAkey", str(ca_key), "-CAcreateserial",
            "-days", "1", "-out", str(self.certificate), "-extfile",
            str(extensions),
        )
        nss_database = Path.home() / ".pki" / "nssdb"
        nss_database.mkdir(parents=True, exist_ok=True)
        if not (nss_database / "cert9.db").is_file():
            self._run(
                "certutil", "-N", "-d", f"sql:{nss_database}",
                "--empty-password",
            )
        self._nickname = f"kerdoos-webrtc-{uuid.uuid4().hex}"
        self._run(
            "certutil", "-A", "-d", f"sql:{nss_database}", "-n",
            self._nickname, "-t", "C,,", "-i", str(ca_certificate),
        )
        self._nss_database = nss_database

    def cleanup(self) -> None:
        subprocess.run(
            [
                "certutil", "-D", "-d", f"sql:{self._nss_database}", "-n",
                self._nickname,
            ],
            check=False,
        )
        self._directory.cleanup()

    @staticmethod
    def _run(*command: str) -> None:
        subprocess.run(command, check=True)


class _UdpCapture:
    def __init__(self) -> None:
        self._events: list[tuple[str, int]] = []
        self._lock = threading.Lock()

    def start(self) -> None:
        threading.Thread(target=self._sniff, daemon=True).start()
        threading.Thread(
            target=self._listen, args=("127.0.0.1", 3478), daemon=True).start()
        threading.Thread(
            target=self._listen, args=("0.0.0.0", 3480), daemon=True).start()
        time.sleep(0.2)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()

    def events(self) -> list[tuple[str, int]]:
        with self._lock:
            return list(self._events)

    def _sniff(self) -> None:
        raw_socket = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        while True:
            frame, address = raw_socket.recvfrom(65535)
            if address[2] == 0 and address[0] != "lo":
                continue
            if (len(frame) < 34 or struct.unpack("!H", frame[12:14])[0] != 0x0800):
                continue
            packet = frame[14:]
            header_length = (packet[0] & 0x0F) * 4
            if packet[9] != socket.IPPROTO_UDP:
                continue
            destination_port = struct.unpack(
                "!H", packet[header_length + 2:header_length + 4])[0]
            if destination_port not in _PRIVATE_PORTS:
                continue
            destination = socket.inet_ntoa(packet[16:20])
            with self._lock:
                self._events.append((destination, destination_port))

    def _listen(self, host: str, port: int) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        while True:
            listener.recvfrom(4096)


def _lan_ip() -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("1.1.1.1", 9))
        return probe.getsockname()[0]
    finally:
        probe.close()


def _webrtc_page(lan_ip: str) -> bytes:
    return f"""<!doctype html><html><body><p id="webrtc-page-loaded">price 123</p>
<img src="/hold">
<script>
(async () => {{
  const pc = new RTCPeerConnection({{iceServers: [
    {{urls: "stun:127.0.0.1:3478"}},
    {{urls: "stun:{lan_ip}:3480"}},
    {{urls: "stun:169.254.169.254:3481"}},
    {{urls: "turn:10.0.0.1:3482?transport=udp", username: "u", credential: "p"}},
  ]}});
  pc.createDataChannel("probe");
  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  let sdp = offer.sdp.trimEnd()
      + "\\r\\na=candidate:1 1 udp 2130706431 127.0.0.1 3479 typ host\\r\\n"
      + "a=candidate:2 1 udp 2130706430 {lan_ip} 3483 typ host\\r\\n";
  await pc.setRemoteDescription({{type: "answer", sdp}});
  for (const candidate of [
      "candidate:3 1 udp 2130706429 127.0.0.1 3479 typ host",
      "candidate:4 1 udp 2130706428 {lan_ip} 3483 typ host",
  ]) {{
    try {{ await pc.addIceCandidate({{candidate, sdpMid: "0", sdpMLineIndex: 0}}); }}
    catch (_) {{}}
  }}
}})();
</script></body></html>""".encode()


class BrowserWebRtcEgressImageTest(unittest.TestCase):
    def setUp(self) -> None:
        if _HAS_PATCHRIGHT and _runtime_certificate_tools_available():
            self._certificate = _NssTrustedCertificate()
            self.addCleanup(self._certificate.cleanup)
            return
        if os.environ.get("KERDOOS_REQUIRE_IMAGE_TESTS") == "1":
            self.fail(
                "KERDOOS_REQUIRE_IMAGE_TESTS=1 but patchright, openssl, or "
                "certutil is unavailable")
        self.skipTest("needs patchright, openssl, and certutil")

    def test_fetch_blocks_unproxied_webrtc_udp_and_keeps_status(self) -> None:
        lan_ip = _lan_ip()
        page = _webrtc_page(lan_ip)

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

        capture = _UdpCapture()
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
            self, capture: _UdpCapture, origin_port: int) -> None:
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
