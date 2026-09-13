"""Hardening: enforce the hexagonal import invariants statically (spec).

  * core/ imports no third-party fetch/parse tool, and no concrete adapter.
  * autolycos/ never imports core/ (extractibility invariant).
  * the port/error modules core relies on stay tool-free (so core cannot pull a
    tool transitively).
"""

from __future__ import annotations

import ast
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
AUTOLYCOS_SRC = ROOT / "packages" / "autolycos" / "src" / "autolycos"
KERDOOS_SRC = ROOT / "packages" / "kerdoos" / "src" / "kerdoos"

TOOLS = {"requests", "curl_cffi", "playwright", "patchright",
         "playwright_stealth", "seleniumbase", "selenium", "bs4", "httpx",
         "yaml", "argon2", "mcp"}

# Concrete adapter / wiring module suffixes that core must never import.
CONCRETE_SUFFIXES = ("adapters", "router", "factory",
                     "sqlite_store", "yaml_store")


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


class ImportContractTest(unittest.TestCase):
    def test_core_imports_no_third_party_tool(self) -> None:
        for f in _py_files(KERDOOS_SRC / "core"):
            for name in _imports(f):
                self.assertNotIn(
                    name.split(".")[0], TOOLS,
                    f"{f.relative_to(ROOT)} imports forbidden tool {name!r}",
                )

    def test_core_imports_no_concrete_adapter(self) -> None:
        for f in _py_files(KERDOOS_SRC / "core"):
            for name in _imports(f):
                offending = (".adapters" in name
                             or name.endswith(CONCRETE_SUFFIXES))
                self.assertFalse(
                    offending,
                    f"{f.relative_to(ROOT)} imports concrete module {name!r}",
                )

    def test_autolycos_never_imports_core(self) -> None:
        for f in _py_files(AUTOLYCOS_SRC):
            for name in _imports(f):
                top = name.split(".")[0]
                self.assertNotIn(
                    top, ("core", "kerdoos"),
                    f"{f.relative_to(ROOT)} imports {top!r} (extractibility "
                    "invariant: autolycos never imports kerdoos/core)",
                )

    def test_mcp_interface_never_imports_autolycos(self) -> None:
        files = _py_files(KERDOOS_SRC / "interfaces" / "mcp")
        self.assertTrue(files, "no module found under kerdoos/interfaces/mcp")
        for f in files:
            for name in _imports(f):
                self.assertNotEqual(
                    name.split(".")[0], "autolycos",
                    f"{f.relative_to(ROOT)} imports {name!r}: MCP tools reach "
                    "fetching only through AppService and RunQueue",
                )

    def test_core_port_dependencies_are_tool_free(self) -> None:
        # Modules core is allowed to import must not drag a tool in.
        port_modules = [
            AUTOLYCOS_SRC / "ports.py",
            AUTOLYCOS_SRC / "errors.py",
            AUTOLYCOS_SRC / "__init__.py",
            # safety.py is the shared anti-SSRF choke point imported by the
            # registry loader; it must stay tool-free (stdlib + .errors only)
            # so a future tool import in the SSRF guard breaks this test.
            AUTOLYCOS_SRC / "safety.py",
            # challenge.py is the shared challenge heuristic imported by every
            # fetcher adapter; it must stay tool-free (pure stdlib) so the
            # cross-tier `challenged` signal never drags a tool in.
            AUTOLYCOS_SRC / "challenge.py",
            KERDOOS_SRC / "parsers" / "ports.py",
            KERDOOS_SRC / "persistence" / "ports.py",
            # auth ports back AuthService (core.app.auth); they must stay
            # tool-free so the Argon2/sqlite adapters never leak into core.
            KERDOOS_SRC / "auth" / "ports.py",
        ]
        for f in port_modules:
            for name in _imports(f):
                self.assertNotIn(
                    name.split(".")[0], TOOLS,
                    f"{f.relative_to(ROOT)} (a core dependency) imports {name!r}",
                )


if __name__ == "__main__":
    unittest.main()
