"""Convention: no fixture under packages/autolycos/tests/fixtures/ may carry
an identifying value (client IP, cookie, tracker id, location, JWT,
personal email). This directory is published as-is into the public
VOCSAP/autolycos repo by `git subtree split --prefix=packages/autolycos`,
so a leak here ships even if the kerdoos-side copy is clean.

Exceptions are per (file, key) only, never global, so a legitimate public
value in one fixture cannot blanket-whitelist the same key elsewhere.

Deliberately duplicated from kerdoos's own tests/test_fixture_privacy.py
rather than imported: autolycos never imports kerdoos (extractibility
invariant), so its privacy scan must stand on its own.
"""

from __future__ import annotations

import ipaddress
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES_DIR = ROOT / "tests" / "fixtures"

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

# (filename, key) -> the one value that key is allowed to carry in that
# file. Never applies to the same key in a different file.
EXCEPTIONS: dict[tuple[str, str], str] = {
    ("magalu_238968700_camoufox.html", "ak.gh"): "2.17.42.146",
    ("magalu_bab5438g3h_camoufox.html", "ak.gh"): "2.17.42.146",
    ("magalu_bab5438g3h_camoufox.html", "zipcode"): "92990000",
    ("magalu_uc.html", "zipcode"): "92990000",
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


def _is_placeholder_cookie(value: str) -> bool:
    if value.strip() == "":
        return True
    lowered = value.lower()
    return "placeholder" in lowered or "redacted" in lowered or "scrubbed" in lowered


def _apply_exception(filename: str, key: str, value: str,
                      violations: list[tuple[str, str]]) -> None:
    if EXCEPTIONS.get((filename, key)) == value:
        return
    violations.append((key, value))


def find_violations(text: str, filename: str) -> list[tuple[str, str]]:
    """Every (key, value) pair in `text` that looks identifying, after
    applying the (filename, key) exception table. `filename` is the bare
    name the exception table is keyed on, not a path."""
    violations: list[tuple[str, str]] = []
    # spans already attributed to a specific key, so the generic ipv4/ipv6
    # sweep below does not re-flag the same value under a second label.
    consumed: list[tuple[int, int]] = []

    m = re.search(r'"x-forwarded-for"\s*:\s*"([^"]*)"', text, re.I)
    if m:
        consumed.append(m.span(1))
        tokens = [t.strip() for t in m.group(1).split(",") if t.strip()]
        if any(_is_public_ipv4(t) for t in tokens):
            _apply_exception(filename, "x-forwarded-for", m.group(1), violations)

    for m in re.finditer(r'"cookie"\s*:\s*"([^"]*)"', text, re.I):
        if not _is_placeholder_cookie(m.group(1)):
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
        (r'"?remoteAddress"?\s*[:=]\s*"?([0-9a-fA-F:.]+)"?', "remoteAddress"),
        (r'"?user[_]?[iI]p"?\s*[:=]\s*"?([0-9a-fA-F:.]+)"?', "userIp"),
    ):
        for m in re.finditer(key_pattern, text):
            value = m.group(1)
            consumed.append(m.span(1))
            if _is_public_ipv4(value) or _is_global_ipv6(value):
                _apply_exception(filename, label, value, violations)

    for m in re.finditer(r'"userLocation"\s*:\s*(\{[^}]*\}|"[^"]*")', text):
        value = m.group(1)
        if value not in ("{}", '""'):
            _apply_exception(filename, "userLocation", value, violations)

    for m in re.finditer(
            r'(?:"(zip[Cc]ode|zip_code|cep|CEP)"\s*:\s*"?(\d{5,9})|'
            r'zipcode=(\d{5,9}))', text):
        value = m.group(2) or m.group(3)
        if value and not _is_zeroed(value):
            _apply_exception(filename, "zipcode", value, violations)

    for m in re.finditer(r'traceparent["\']?\s*[:=]\s*["\']?([0-9a-fA-F-]{10,})',
                          text, re.I):
        if _nonzero_hex_count(m.group(1)) > 0:
            _apply_exception(filename, "traceparent", m.group(1), violations)

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


class FixturePrivacyTest(unittest.TestCase):
    def test_scans_a_nonzero_number_of_fixture_files(self) -> None:
        files = sorted(FIXTURES_DIR.glob("*.html"))
        self.assertGreater(
            len(files), 0,
            f"no .html fixture found under {FIXTURES_DIR} -- a scan over an "
            "empty directory must not read as a passing scan")

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
            ("userLocation", '{"userLocation":{"city":"Sao Paulo","lat":-23.55}}'),
            ("zipcode", '{"address":{"zipcode":"01311000"}}'),
            ("traceparent", 'traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"'),
            ("ipv4", '{"host":"93.184.216.34"}'),
            ("ipv6", '{"host":"2606:2800:220:1:248:1893:25c8:1946"}'),
            ("jwt", jwt_witness),
            ("email", '{"contact":"joao.silva@gmail.com"}'),
        ]
        for label, snippet in witnesses:
            with self.subTest(motif=label):
                violations = find_violations(snippet, "witness.html")
                keys = [k for k, _ in violations]
                self.assertIn(
                    label, keys,
                    f"a {label} witness with a real-looking value must be "
                    f"caught, found violations={violations!r}")

    def test_negative_controls_stay_clean(self) -> None:
        witnesses = [
            ("rfc5737 ipv4", '{"remoteAddress":"203.0.113.7"}'),
            ("private ipv4", '{"remoteAddress":"10.0.0.5"}'),
            ("loopback ipv4", '{"remoteAddress":"127.0.0.1"}'),
            ("placeholder cookie", '{"cookie":"placeholder_cookie=true"}'),
            ("nulled rua.trans", '{"rua.trans":"SJ-00000000-0000-4000-8000-000000000001"}'),
            ("nulled ak.rid", '{"ak.rid":"00000000"}'),
            ("nulled ak.cport", '{"ak.cport":"0"}'),
            ("nulled traceparent", 'traceparent: "00-00000000000000000000000000000000-0000000000000000-00"'),
            ("empty userLocation", '{"userLocation":{}}'),
            ("empty zipcode", '{"zipcode":""}'),
            ("nulled zipcode", '{"zipcode":"00000"}'),
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

    def test_no_identifying_value_in_the_current_fixtures(self) -> None:
        files = sorted(FIXTURES_DIR.glob("*.html"))
        report: dict[str, list[tuple[str, str]]] = {}
        for f in files:
            violations = find_violations(
                f.read_text(encoding="utf-8", errors="replace"), f.name)
            if violations:
                report[f.name] = violations
        self.assertEqual(
            report, {},
            "identifying value(s) found in committed fixtures (public repo): "
            f"{report!r}")


if __name__ == "__main__":
    unittest.main()
