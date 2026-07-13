"""Digest HTML template registry (ADR 0003 Phase 6b tranche 4, security
finding S5 CWE-22/1336).

TEMPLATE_FILES is a server-side lookup dict: template_id -> filename. This
module NEVER interpolates template_id into a filesystem path (e.g.
f"{template_id}.html") -- the only way to reach an actual file on disk is
through this dict's values, which are hardcoded literals, not derived from
caller input. Combined with registry.ports.validate_template_id (the
write-time gate), this closes the authoring/render TOCTOU: even if a
template_id somehow reached this function without passing validate_template_id
first (a future write path that forgets to call it, or a value written before
that validator existed), render_digest_html still refuses anything outside
this dict instead of falling back to any path-like behavior.

tests/test_digest_template_registry.py asserts
set(TEMPLATE_FILES) == VALID_TEMPLATE_IDS, keeping this module and
registry.ports's whitelist from drifting apart.

The Jinja2 Environment has autoescape=True (S3 CWE-79): every DigestView
string field is HTML-escaped by default. Nothing here disables autoescape
for any template.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from kerdoos.digest.view import DigestView

TEMPLATE_FILES: dict[str, str] = {
    "default": "default.html",
}

_TEMPLATES_DIR = Path(__file__).parent / "templates"

_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=select_autoescape(enabled_extensions=("html",), default=True),
)


def render_digest_html(template_id: str, view: DigestView) -> str:
    filename = TEMPLATE_FILES.get(template_id)
    if filename is None:
        raise ValueError(f"unknown template_id {template_id!r}")
    template = _env.get_template(filename)
    return template.render(view=view)
