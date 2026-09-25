from __future__ import annotations

import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path

_PRIVATE_PORTS = frozenset({3478, 3479, 3480, 3481, 3482, 3483})


def runtime_certificate_tools_available() -> bool:
    if shutil.which("openssl") is None:
        return False
    certutil = shutil.which("certutil")
    if certutil is None:
        return False
    try:
        result = subprocess.run(
            [certutil, "-H"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            check=False,
        )
    except OSError:
        return False
    return (
        result.returncode == 1
        and "Add a certificate to the database" in result.stdout
    )


class NssTrustedCertificate:
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


class UdpCapture:
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


def lan_ip() -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("1.1.1.1", 9))
        return probe.getsockname()[0]
    finally:
        probe.close()


def webrtc_page(lan_ip: str) -> bytes:
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
