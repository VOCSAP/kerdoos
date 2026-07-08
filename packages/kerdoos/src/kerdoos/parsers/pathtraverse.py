"""Safe token path traverser (spec HIGH-1, CWE-95/502).

Resolves a dotted path like `props.pageProps.product.prices.price` or
`offers[0].price` against an already-parsed JSON structure (dict/list of
primitives). Deliberately minimal and non-reflective:

  * the path is split on '.' into tokens;
  * a token is `name` optionally followed by one or more `[n]` indices;
  * indices are parsed with int() only;
  * dict access is plain subscription (obj[name]); list access is obj[int];
  * NO getattr, NO eval, NO dunder access, NO attribute traversal.

Any structural miss (missing key, non-container, out-of-range index, malformed
token) raises PathResolutionError. Callers decide how to map that to the domain
(price miss -> ParseError -> INDETERMINATE; availability miss -> UNKNOWN).
"""

from __future__ import annotations

from typing import Any


class PathResolutionError(Exception):
    """The path could not be resolved against the given structure."""


def _parse_token(token: str) -> tuple[str, list[int]]:
    """Split `name[0][1]` into ("name", [0, 1]). Reject malformed brackets."""
    if not token:
        raise PathResolutionError("empty path token")
    name = token
    indices: list[int] = []
    bracket = token.find("[")
    if bracket != -1:
        name = token[:bracket]
        rest = token[bracket:]
        # rest must be a sequence of [digits] groups only.
        while rest:
            if not rest.startswith("["):
                raise PathResolutionError(f"malformed index in token {token!r}")
            close = rest.find("]")
            if close == -1:
                raise PathResolutionError(f"unclosed index in token {token!r}")
            inner = rest[1:close]
            if not inner or not inner.lstrip("-").isdigit():
                raise PathResolutionError(f"non-integer index in token {token!r}")
            indices.append(int(inner))
            rest = rest[close + 1:]
    return name, indices


def resolve_path(data: Any, path: str) -> Any:
    """Traverse `data` following `path`. Raise PathResolutionError on any miss."""
    if not path:
        raise PathResolutionError("empty path")
    node = data
    for token in path.split("."):
        name, indices = _parse_token(token)
        if name:
            if not isinstance(node, dict):
                raise PathResolutionError(
                    f"expected dict for key {name!r}, got {type(node).__name__}"
                )
            if name not in node:
                raise PathResolutionError(f"missing key {name!r}")
            node = node[name]
        for idx in indices:
            if not isinstance(node, list):
                raise PathResolutionError(
                    f"expected list for index [{idx}], got {type(node).__name__}"
                )
            if idx < 0 or idx >= len(node):
                raise PathResolutionError(f"index [{idx}] out of range")
            node = node[idx]
    return node
