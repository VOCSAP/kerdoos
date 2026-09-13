"""Startup validation of KERDOOS_FORWARDED_ALLOW_IPS for the image's CMD.

Run as `python -m kerdoos.interfaces.web.forwarded_allow_ips` before uvicorn:
exit 0 to launch, exit 64 (EX_USAGE) to refuse.

The predicate is derived from the CONSUMER, uvicorn's `_TrustedHosts`, not
from the spelling of the value. uvicorn splits on commas, strips each element
and hands anything containing "/" to `ipaddress.ip_network`, so a textual
match on "/0" misses `0.0.0.0/00`, the netmask form `0.0.0.0/0.0.0.0`, and the
two-halves union `0.0.0.0/1,128.0.0.0/1`. Parsing the same way is the only
way to close the class rather than the spellings found so far.
"""

from __future__ import annotations

import ipaddress
import os
import sys

_ENV_VAR = "KERDOOS_FORWARDED_ALLOW_IPS"

# Widest prefix a real proxy can be announced on. /8 admits both private
# ranges an operator may legitimately name (10.0.0.0/8, fd00::/8) while
# closing /0 in every spelling and the /1 unions, since each element is
# judged on its own. RFC 4193 leaves fc00::/8 unassigned, so fd00::/8 already
# covers every ULA in use and nothing operational needs a wider prefix.
_MIN_PREFIXLEN = 8


def offending_element(value: str) -> str | None:
    """Return the element that would trust too much, or None if all are fine.

    Mirrors uvicorn's `_parse_raw_hosts`: split on "," then strip, so the
    value is judged on exactly the text uvicorn will parse.
    """
    for element in (item.strip() for item in value.split(",")):
        # Refused by assumed strictness, not because it trusts everyone:
        # uvicorn only sets always_trust when the WHOLE value is exactly "*",
        # so "10.0.0.1,*" and even " * " leave it an inert literal.
        if element == "*":
            return element
        if "/" not in element:
            continue
        try:
            network = ipaddress.ip_network(element)
        except ValueError:
            # Not a network: uvicorn keeps it as a literal, which trusts
            # nothing by itself.
            continue
        if network.prefixlen < _MIN_PREFIXLEN:
            return element
    return None


def main() -> int:
    value = os.environ.get(_ENV_VAR, "")
    element = offending_element(value)
    if element is None:
        return 0
    # Both the value and the element are named: under `restart:
    # unless-stopped` an operator sees only "Restarting (64)", so this log
    # line is the single place the cause is visible.
    print(
        f"{_ENV_VAR}={value!r} is refused: the entry {element!r} trusts far "
        f"more than a proxy (an address, or a network of at least "
        f"/{_MIN_PREFIXLEN}, is expected). Any trusted address can forge the "
        f"client IP.",
        file=sys.stderr,
    )
    return 64


if __name__ == "__main__":
    sys.exit(main())
