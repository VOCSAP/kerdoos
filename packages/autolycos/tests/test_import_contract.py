"""Hardening: enforce autolycos's own extractibility invariants (spec).

  * autolycos/ never imports core/kerdoos, including a lazy import inside a
    function body (the package defers `camoufox`/`playwright`/`psutil`
    imports into functions on purpose, so a stray kerdoos import could hide
    the same way).
  * the port/error/challenge modules it exposes stay tool-free, so a
    downstream core built on top of autolycos cannot pull a tool in
    transitively through them.

Kerdoos checks the mirror invariants (core imports no tool, MCP never
imports autolycos) from its own test file (tests/test_import_contract.py).
"""

from __future__ import annotations

import ast
import pathlib
import unittest

AUTOLYCOS_SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "autolycos"

TOOLS = {"requests", "curl_cffi", "playwright", "patchright",
         "playwright_stealth", "seleniumbase", "selenium", "bs4", "httpx",
         "yaml", "argon2", "mcp", "camoufox", "psutil"}


def _imports(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                names.add(node.module)
    return names


def _py_files(base: pathlib.Path) -> list[pathlib.Path]:
    return sorted(base.rglob("*.py"))


class AutolycosImportContractTest(unittest.TestCase):
    def test_never_imports_core_or_kerdoos(self) -> None:
        for f in _py_files(AUTOLYCOS_SRC):
            for name in _imports(f):
                top = name.split(".")[0]
                self.assertNotIn(
                    top, ("core", "kerdoos"),
                    f"{f.relative_to(AUTOLYCOS_SRC.parent)} imports {top!r} "
                    "(extractibility invariant: autolycos never imports "
                    "kerdoos/core)",
                )

    def test_port_dependencies_are_tool_free(self) -> None:
        port_modules = [
            AUTOLYCOS_SRC / "ports.py",
            AUTOLYCOS_SRC / "errors.py",
            AUTOLYCOS_SRC / "__init__.py",
            AUTOLYCOS_SRC / "safety.py",
            AUTOLYCOS_SRC / "challenge.py",
        ]
        for f in port_modules:
            for name in _imports(f):
                self.assertNotIn(
                    name.split(".")[0], TOOLS,
                    f"{f.name} (a port/error dependency) imports {name!r}",
                )


if __name__ == "__main__":
    unittest.main()
