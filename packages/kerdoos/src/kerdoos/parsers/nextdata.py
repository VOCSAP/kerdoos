"""Shared __NEXT_DATA__ extractor (Next.js embedded state).

Hoisted out of the statejson adapter so any parser reading a Next.js page's
inlined state JSON (statejson/Kabum, magalu, ...) uses the SAME capture. Pure
stdlib (html.parser only); no tool imports, no core import.
"""

from __future__ import annotations

from html.parser import HTMLParser


class _NextDataExtractor(HTMLParser):
    """Capture the text content of <script id="__NEXT_DATA__">."""

    def __init__(self) -> None:
        super().__init__()
        self._capture = False
        self._buf: list[str] = []
        self.data: str | None = None

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        if tag == "script" and dict(attrs).get("id") == "__NEXT_DATA__":
            self._capture = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._capture:
            self._capture = False
            if self.data is None:
                self.data = "".join(self._buf)

    def handle_data(self, data: str) -> None:
        if self._capture:
            self._buf.append(data)


def extract_next_data(html: str) -> str | None:
    """Return the raw JSON text of the __NEXT_DATA__ script, or None if absent."""
    parser = _NextDataExtractor()
    parser.feed(html)
    parser.close()
    return parser.data
