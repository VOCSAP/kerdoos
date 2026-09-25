"""Convention: no fixture under packages/autolycos/tests/fixtures/ may carry
an identifying value (client IP, cookie, tracker id, location, JWT,
personal email). This directory is published as-is into the public
VOCSAP/autolycos repo by `git subtree split --prefix=packages/autolycos`,
so a leak here ships even if the kerdoos-side copy is clean.

Exceptions are per (file, key) only, never global, so a legitimate public
value in one fixture cannot blanket-whitelist the same key elsewhere.

`scan_directory` reads every occurrence through 3 views of the same bytes
(raw, HTML-entity-unescaped, JSON-quote-unescaped + URL-unquoted) because a
value can hide from the raw-text regexes behind `&quot;` or a `\"` escape
without ceasing to be the same identifying value once decoded.

Deliberately duplicated from kerdoos's own tests/test_fixture_privacy.py
rather than imported: autolycos never imports kerdoos (extractibility
invariant), so its privacy scan must stand on its own.
"""

from __future__ import annotations

import html
import ipaddress
import pathlib
import re
import tempfile
import unittest
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES_DIR = ROOT / "tests" / "fixtures"

ALLOWED_EXTENSIONS = {".html"}

RFC5737 = [ipaddress.ip_network(n) for n in
           ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]

# Local-part prefixes accepted as a vendor's published support contact
# rather than a personal address (the "hors support public" carve-out).
SUPPORT_EMAIL_PREFIXES = ("suporte", "support", "ajuda", "help",
                           "atendimento", "sac", "contato", "contact")

# @2x/@3x asset-density suffixes read as an email by a naive regex
# (e.g. "logo_large@2x.webp"); not an email, never a finding.
ASSET_EXTENSIONS = ("webp", "png", "jpg", "jpeg", "gif", "svg", "ico",
                     "css", "js")

# device/session identifier keys that must never carry a non-placeholder
# value in a committed fixture.
IDENTIFIER_KEYS = ("_d2id", "deviceId", "device_id", "session-id", "sessionId",
                    "session_id", "x-request-id", "requestId", "correlation_id",
                    "c_uid", "csrfToken")

LATLON_KEYS = ("latitude", "longitude", "lat", "lng", "lon", "long")

# (filename, key) -> the one value that key is allowed to carry in that
# file. Never applies to the same key in a different file.
EXCEPTIONS: dict[tuple[str, str], str] = {
    ("magalu_238968700_camoufox.html", "ak.gh"): "2.17.42.146",
    ("magalu_bab5438g3h_camoufox.html", "ak.gh"): "2.17.42.146",
    ("magalu_bab5438g3h_camoufox.html", "zipcode"): "92990000",
    ("magalu_uc.html", "zipcode"): "92990000",
    # public HQ address, JSON-LD Organization block, not a visitor CEP.
    ("terabyte_40561.html", "zipcode"): "80030-001",
}


def _is_public_ipv4(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    if not isinstance(addr, ipaddress.IPv4Address):
        return False
    if (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
        return False
    return not any(addr in net for net in RFC5737)


def _is_global_ipv6(value: str) -> bool:
    if value.count(":") < 2:
        return False
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return isinstance(addr, ipaddress.IPv6Address) and addr.is_global


def _nonzero_hex_count(value: str) -> int:
    return sum(1 for c in value.lower() if c in "123456789abcdef")


def _is_zeroed(value: str) -> bool:
    return bool(re.fullmatch(r"0+", value))


def _is_placeholder_value(value: str) -> bool:
    if value.strip() == "":
        return True
    lowered = value.lower()
    if any(w in lowered for w in ("placeholder", "redacted", "scrubbed")):
        return True
    return bool(re.fullmatch(r"[0x_-]+", lowered))


def _apply_exception(filename: str, key: str, value: str,
                      violations: list[tuple[str, str]]) -> None:
    if EXCEPTIONS.get((filename, key)) == value:
        return
    violations.append((key, value))


def _views(text: str) -> list[str]:
    """3 decodings of the same bytes: a value can hide from the raw-text
    regexes behind an HTML entity (`&quot;`) or a JSON/URL escape (`\\"`,
    `%22`) without ceasing to be the same identifying value once decoded."""
    json_unescaped = urllib.parse.unquote(text.replace('\\"', '"'))
    return [text, html.unescape(text), json_unescaped]


def _scan_view(text: str, filename: str) -> list[tuple[str, str]]:
    violations: list[tuple[str, str]] = []
    # spans already attributed to a specific key, so the generic ipv4/ipv6
    # sweep below does not re-flag the same value under a second label.
    consumed: list[tuple[int, int]] = []

    for m in re.finditer(r'"x-forwarded-for"\s*:\s*"([^"]*)"', text, re.I):
        consumed.append(m.span(1))
        tokens = [t.strip() for t in m.group(1).split(",") if t.strip()]
        if any(_is_public_ipv4(t) for t in tokens):
            _apply_exception(filename, "x-forwarded-for", m.group(1), violations)

    for m in re.finditer(r'"cookie"\s*:\s*"([^"]*)"', text, re.I):
        if not _is_placeholder_value(m.group(1)):
            _apply_exception(filename, "cookie", m.group(1), violations)

    for m in re.finditer(r'"rua\.trans"\s*:\s*"([^"]*)"', text):
        if _nonzero_hex_count(m.group(1)) > 4:
            _apply_exception(filename, "rua.trans", m.group(1), violations)

    for m in re.finditer(r'"ak\.rid"\s*:\s*"?([0-9a-fA-F]*)"?', text):
        value = m.group(1)
        if value and _nonzero_hex_count(value) > 0:
            _apply_exception(filename, "ak.rid", value, violations)

    for m in re.finditer(r'"ak\.cport"\s*:\s*"?(\d*)"?', text):
        value = m.group(1)
        if value not in ("", "0"):
            _apply_exception(filename, "ak.cport", value, violations)

    for m in re.finditer(r'"ak\.gh"\s*:\s*"?([^",}]*)"?', text):
        value = m.group(1)
        consumed.append(m.span(1))
        if _is_public_ipv4(value):
            _apply_exception(filename, "ak.gh", value, violations)

    for key_pattern, label in (
        (r'"?remoteAddress"?\s*[:=]\s*"([^"]*)"', "remoteAddress"),
        (r'"?user[_]?[iI]p"?\s*[:=]\s*"([^"]*)"', "userIp"),
    ):
        for m in re.finditer(key_pattern, text, re.I):
            consumed.append(m.span(1))
            tokens = [t.strip() for t in m.group(1).split(",") if t.strip()]
            if any(_is_public_ipv4(t) or _is_global_ipv6(t) for t in tokens):
                _apply_exception(filename, label, m.group(1), violations)

    for m in re.finditer(r'"userLocation"\s*:\s*(\{[^}]*\}|"[^"]*")', text):
        value = m.group(1)
        if value not in ("{}", '""'):
            _apply_exception(filename, "userLocation", value, violations)

    for m in re.finditer(
            r'(?:"(zip_?[Cc]ode|postal_?[Cc]ode|cep)"\s*:\s*"?(\d{5}-?\d{3}|\d{5})|'
            r'(?:zip_?code|cep)=(\d{5}-?\d{3}|\d{5}))', text, re.I):
        value = m.group(2) or m.group(3)
        if value and not _is_zeroed(value.replace("-", "")):
            _apply_exception(filename, "zipcode", value, violations)

    for m in re.finditer(r'"ak\.ak"\s*:\s*"([^"]*)"', text, re.I):
        value = m.group(1)
        if value and not re.fullmatch(r"[Aa]*", value):
            _apply_exception(filename, "ak.ak", value, violations)

    for m in re.finditer(r'traceparent["\']?\s*[:=]\s*["\']?([0-9a-fA-F-]{10,})',
                          text, re.I):
        if _nonzero_hex_count(m.group(1)) > 0:
            _apply_exception(filename, "traceparent", m.group(1), violations)

    for key_name in IDENTIFIER_KEYS:
        pattern = rf'"{re.escape(key_name)}"\s*:\s*"([^"]*)"'
        for m in re.finditer(pattern, text, re.I):
            value = m.group(1)
            # these ids are shipped in this corpus as UUID-shaped values
            # with only the fixed version/variant hex nibbles left non-zero
            # once scrubbed (same convention as rua.trans); a real id has
            # far more non-zero hex digits than that.
            if value and not _is_placeholder_value(value) and _nonzero_hex_count(value) > 4:
                _apply_exception(filename, key_name, value, violations)

    for key_name in LATLON_KEYS:
        pattern = rf'"{re.escape(key_name)}"\s*:\s*"?(-?\d+\.\d+)"?'
        for m in re.finditer(pattern, text, re.I):
            value = m.group(1)
            decimals = value.split(".", 1)[1] if "." in value else ""
            # 2 decimal places is city-block precision (~1km); more than
            # that pins a location tightly enough to identify a visitor.
            if len(decimals) > 2:
                _apply_exception(filename, key_name, value, violations)

    def _already_consumed(span: tuple[int, int]) -> bool:
        return any(span[0] < c[1] and span[1] > c[0] for c in consumed)

    for m in re.finditer(r'''["']((?:\d{1,3}\.){3}\d{1,3})["']''', text):
        value = m.group(1)
        if _already_consumed(m.span(1)):
            continue
        prefix = text[max(0, m.start() - 40):m.start()]
        # a semver/User-Agent version string ("Chrome/150.0.0.0") is
        # syntactically identical to a dotted-quad IPv4; only a value
        # under a non-version key is treated as a real address.
        if re.search(r'"[^"]*version[^"]*"\s*:\s*$', prefix, re.I):
            continue
        if _is_public_ipv4(value):
            _apply_exception(filename, "ipv4", value, violations)

    for m in re.finditer(r'''["']([0-9a-fA-F:]{2,45})["']''', text):
        if _already_consumed(m.span(1)):
            continue
        if _is_global_ipv6(m.group(1)):
            _apply_exception(filename, "ipv6", m.group(1), violations)

    for m in re.finditer(
            r'eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}', text):
        _apply_exception(filename, "jwt", m.group(0), violations)

    for m in re.finditer(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text):
        local, _, domain = m.group(0).partition("@")
        tld = domain.rsplit(".", 1)[-1].lower()
        if tld in ASSET_EXTENSIONS:
            continue
        if local.lower().startswith(SUPPORT_EMAIL_PREFIXES):
            continue
        _apply_exception(filename, "email", m.group(0), violations)

    return violations


def find_violations(text: str, filename: str) -> list[tuple[str, str]]:
    """Every (key, value) pair that looks identifying in ANY of the 3
    decodings of `text` (see `_views`), after applying the (filename, key)
    exception table. `filename` is the bare name the exception table is
    keyed on, not a path."""
    violations: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for view in _views(text):
        for pair in _scan_view(view, filename):
            if pair not in seen:
                seen.add(pair)
                violations.append(pair)
    return violations


def scan_directory(directory: pathlib.Path) -> dict[str, list[tuple[str, str]]]:
    """The real production scan path: every file under `directory`
    (recursive), not just the ones a caller remembered to ask for. Raises
    loudly on an empty directory (a scan that reads nothing must not read as
    a scan that passed) and on any extension outside `ALLOWED_EXTENSIONS`
    (a new fixture format ships unscanned otherwise, silently)."""
    files = sorted(p for p in directory.rglob("*") if p.is_file())
    if not files:
        raise AssertionError(
            f"no fixture file found under {directory} -- an empty "
            "directory must not read as a passing scan")
    report: dict[str, list[tuple[str, str]]] = {}
    for f in files:
        if f.suffix.lower() not in ALLOWED_EXTENSIONS:
            raise AssertionError(
                f"{f.relative_to(directory)}: extension {f.suffix!r} is "
                f"not in the scanned allowlist {sorted(ALLOWED_EXTENSIONS)} "
                "-- add it there or remove the file, do not let it slip "
                "through unscanned")
        violations = find_violations(
            f.read_text(encoding="utf-8", errors="replace"), f.name)
        if violations:
            report[f.name] = violations
    return report


class FixturePrivacyTest(unittest.TestCase):
    def test_scans_a_nonzero_number_of_fixture_files(self) -> None:
        files = sorted(FIXTURES_DIR.glob("*.html"))
        self.assertGreater(
            len(files), 0,
            f"no .html fixture found under {FIXTURES_DIR} -- a scan over an "
            "empty directory must not read as a passing scan")

    def test_an_empty_fixtures_directory_fails_the_scan(self) -> None:
        with tempfile.TemporaryDirectory() as empty_dir:
            with self.assertRaises(
                    AssertionError,
                    msg="a directory with 0 files must not read as a "
                    "passing scan"):
                scan_directory(pathlib.Path(empty_dir))

    def test_an_unexpected_extension_fails_the_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            leftover = pathlib.Path(tmp_dir) / "dump.json"
            leftover.write_text('{"remoteAddress":"177.10.20.30"}',
                                 encoding="utf-8")
            with self.assertRaises(
                    AssertionError,
                    msg="a file extension outside the allowlist must fail "
                    "the scan loudly instead of being silently skipped"):
                scan_directory(pathlib.Path(tmp_dir))

    def test_positive_control_each_pattern_is_detected(self) -> None:
        # built from parts so no contiguous JWT-shaped literal sits in the
        # source tree for a secret scanner to (rightly) flag on a witness
        # value that only needs to match the JWT *shape*, not be a real token.
        jwt_witness = ".".join((
            "eyJhbGciOiJIUzI1NiJ9",
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
            "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        ))
        witnesses = [
            ("x-forwarded-for", '{"headers":{"x-forwarded-for":"177.10.20.30","cookie":"placeholder_cookie=true"}}'),
            ("cookie", '{"headers":{"cookie":"sessionid=abc123xyz; csrftoken=deadbeef42"}}'),
            ("rua.trans", '{"rua.trans":"SJ-a1b2c3d4-e5f6-4a7b-8c9d-0123456789ab"}'),
            ("ak.rid", '{"ak.rid":"a3f9c1e2"}'),
            ("ak.cport", '{"ak.cport":"54231"}'),
            ("ak.gh", '{"ak.gh":"93.184.216.34"}'),
            ("remoteAddress", '{"remoteAddress":"177.10.20.30"}'),
            ("userIp", '{"userIp":"177.10.20.30"}'),
            ("remoteAddress (2nd of a list)", '{"remoteAddress":"10.0.0.1, 177.10.20.30"}'),
            ("userLocation", '{"userLocation":{"city":"Sao Paulo","lat":-23.55}}'),
            ("zipcode", '{"address":{"zipcode":"01311000"}}'),
            ("postal_code", '{"address":{"postal_code":"01311000"}}'),
            ("cep query form", 'href="/menu?cep=01311000"'),
            ("_d2id", '{"_d2id":"a1b2c3d4e5f6"}'),
            ("deviceId", '{"deviceId":"a1b2c3d4e5f6"}'),
            ("session-id", '{"session-id":"a1b2c3d4e5f6"}'),
            ("latitude", '{"latitude":-23.6821604}'),
            ("longitude", '{"longitude":-46.875494}'),
            ("ak.ak", '{"ak.ak":"hOBiQwZUYzCg5VSAfCLimQ=="}'),
            ("traceparent", 'traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"'),
            ("ipv4", '{"host":"93.184.216.34"}'),
            ("ipv6", '{"host":"2606:2800:220:1:248:1893:25c8:1946"}'),
            ("jwt", jwt_witness),
            ("email", '{"contact":"joao.silva@gmail.com"}'),
            ("html-entity-escaped zipcode", '&quot;zipcode&quot;:&quot;01311000&quot;'),
            ("JSON-escaped remoteAddress", '{\\"remoteAddress\\":\\"177.10.20.30\\"}'),
            ("URL-encoded cep query", 'href="/menu?cep%3D01311000"'),
            ("mixed-case ZipCode", '{"ZipCode":"01311000"}'),
            ("uppercase CEP", 'href="/menu?CEP=01311000"'),
            ("mixed-case Latitude", '{"Latitude":-23.6821604}'),
            ("3-decimal latitude", '{"latitude":-23.682}'),
            ("lon", '{"lon":-46.875494}'),
            ("long", '{"long":-46.875494}'),
            ("2nd x-forwarded-for header carries the real IP", '{"h1":{"x-forwarded-for":"10.0.0.1"}},{"h2":{"x-forwarded-for":"177.10.20.30"}}'),
            ("session_id", '{"session_id":"a1b2c3d4e5f6"}'),
            ("x-request-id", '{"x-request-id":"a1b2c3d4e5f6"}'),
            ("requestId", '{"requestId":"a1b2c3d4e5f6"}'),
            ("correlation_id", '{"correlation_id":"a1b2c3d4e5f6"}'),
            ("c_uid", '{"c_uid":"a1b2c3d4e5f6"}'),
            ("csrfToken", '{"csrfToken":"a1b2c3d4e5f6"}'),
            ("mixed-case SessionId", '{"SESSION_ID":"a1b2c3d4e5f6"}'),
        ]
        for label, snippet in witnesses:
            with self.subTest(motif=label):
                violations = find_violations(snippet, "witness.html")
                keys = [k for k, _ in violations]
                expected_key = {
                    "remoteAddress (2nd of a list)": "remoteAddress",
                    "postal_code": "zipcode",
                    "cep query form": "zipcode",
                    "html-entity-escaped zipcode": "zipcode",
                    "JSON-escaped remoteAddress": "remoteAddress",
                    "URL-encoded cep query": "zipcode",
                    "mixed-case ZipCode": "zipcode",
                    "uppercase CEP": "zipcode",
                    "mixed-case Latitude": "latitude",
                    "3-decimal latitude": "latitude",
                    "2nd x-forwarded-for header carries the real IP": "x-forwarded-for",
                    "mixed-case SessionId": "session_id",
                }.get(label, label)
                self.assertIn(
                    expected_key, keys,
                    f"a {label} witness with a real-looking value must be "
                    f"caught, found violations={violations!r}")

    def test_negative_controls_stay_clean(self) -> None:
        witnesses = [
            ("rfc5737 ipv4", '{"remoteAddress":"203.0.113.7"}'),
            ("private ipv4", '{"remoteAddress":"10.0.0.5"}'),
            ("loopback ipv4", '{"remoteAddress":"127.0.0.1"}'),
            ("remoteAddress list, all private/rfc5737", '{"remoteAddress":"10.0.0.1, 203.0.113.7"}'),
            ("placeholder cookie", '{"cookie":"placeholder_cookie=true"}'),
            ("nulled rua.trans", '{"rua.trans":"SJ-00000000-0000-4000-8000-000000000001"}'),
            ("nulled ak.rid", '{"ak.rid":"00000000"}'),
            ("nulled ak.cport", '{"ak.cport":"0"}'),
            ("nulled traceparent", 'traceparent: "00-00000000000000000000000000000000-0000000000000000-00"'),
            ("empty userLocation", '{"userLocation":{}}'),
            ("empty zipcode", '{"zipcode":""}'),
            ("nulled zipcode", '{"zipcode":"00000"}'),
            ("nulled _d2id", '{"_d2id":"00000000"}'),
            ("placeholder deviceId", '{"deviceId":"placeholder"}'),
            ("city-precision latitude", '{"latitude":-23.68}'),
            ("city-precision longitude", '{"longitude":-46.87}'),
            ("placeholder ak.ak", '{"ak.ak":"AAAAAAAAAAAAAAAAAAAAAAAA"}'),
            ("empty ak.ak", '{"ak.ak":""}'),
            ("support email", '{"contact":"suporte@loja.com.br"}'),
            ("asset filename, not an email", '"logo_large_plus@2x.webp"'),
            ("version string, not an ipv4", '{"engine":{"version":"150.0.0.0"}}'),
        ]
        for label, snippet in witnesses:
            with self.subTest(case=label):
                violations = find_violations(snippet, "witness.html")
                self.assertEqual(
                    violations, [],
                    f"{label} must not be flagged, found {violations!r}")

    def test_exception_does_not_apply_outside_its_own_file(self) -> None:
        snippet = '{"ak.gh":"2.17.42.146"}'
        self.assertEqual(
            find_violations(snippet, "magalu_238968700_camoufox.html"), [],
            "ak.gh=2.17.42.146 is exempted in its own file")
        self.assertEqual(
            find_violations(snippet, "some_other_site_dump.html"),
            [("ak.gh", "2.17.42.146")],
            "the same value in a file NOT on the exception list must still "
            "be flagged -- an exception is per (file, key), never global")

    def test_zipcode_exception_matches_the_exact_value_not_a_prefix(self) -> None:
        self.assertEqual(
            find_violations('{"postalCode":"80030-001"}', "terabyte_40561.html"),
            [],
            "80030-001 is the vendor's own exempted HQ address (JSON-LD "
            "Organization block)")
        self.assertEqual(
            find_violations('{"postalCode":"80030-999"}', "terabyte_40561.html"),
            [("zipcode", "80030-999")],
            "a different CEP sharing the same 80030 prefix must still be "
            "flagged -- the exception matches the exact value, not a prefix")

    def test_no_identifying_value_in_the_current_fixtures(self) -> None:
        report = scan_directory(FIXTURES_DIR)
        self.assertEqual(
            report, {},
            "identifying value(s) found in committed fixtures (public repo): "
            f"{report!r}")


if __name__ == "__main__":
    unittest.main()
