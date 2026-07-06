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

TOOLS = {"requests", "curl_cffi", "playwright", "seleniumbase",
         "selenium", "bs4", "httpx", "yaml"}

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


def _py_files(pkg: str) -> list[pathlib.Path]:
    return sorted((ROOT / pkg).rglob("*.py"))


class ImportContractTest(unittest.TestCase):
    def test_core_imports_no_third_party_tool(self) -> None:
        for f in _py_files("core"):
            for name in _imports(f):
                self.assertNotIn(
                    name.split(".")[0], TOOLS,
                    f"{f.relative_to(ROOT)} imports forbidden tool {name!r}",
                )

    def test_core_imports_no_concrete_adapter(self) -> None:
        for f in _py_files("core"):
            for name in _imports(f):
                offending = (".adapters" in name
                             or name.endswith(CONCRETE_SUFFIXES))
                self.assertFalse(
                    offending,
                    f"{f.relative_to(ROOT)} imports concrete module {name!r}",
                )

    def test_autolycos_never_imports_core(self) -> None:
        for f in _py_files("autolycos"):
            for name in _imports(f):
                self.assertNotEqual(
                    name.split(".")[0], "core",
                    f"{f.relative_to(ROOT)} imports core ({name!r})",
                )

    def test_core_port_dependencies_are_tool_free(self) -> None:
        # Modules core is allowed to import must not drag a tool in.
        port_modules = [
            ROOT / "autolycos" / "ports.py",
            ROOT / "autolycos" / "errors.py",
            ROOT / "autolycos" / "__init__.py",
            # safety.py is the shared anti-SSRF choke point imported by the
            # registry loader; it must stay tool-free (stdlib + .errors only)
            # so a future tool import in the SSRF guard breaks this test.
            ROOT / "autolycos" / "safety.py",
            ROOT / "parsers" / "ports.py",
            ROOT / "persistence" / "ports.py",
        ]
        for f in port_modules:
            for name in _imports(f):
                self.assertNotIn(
                    name.split(".")[0], TOOLS,
                    f"{f.relative_to(ROOT)} (a core dependency) imports {name!r}",
                )


if __name__ == "__main__":
    unittest.main()
