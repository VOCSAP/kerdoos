"""Hardening: enforce the hexagonal import invariants statically (spec).

  * core/ imports no third-party fetch/parse tool, and no concrete adapter.
  * autolycos/ never imports core/ (extractibility invariant).
  * the port/error modules core relies on stay tool-free (so core cannot pull a
    tool transitively).

autolycos's own source is located via the RESOLVED, installed package
(importlib.util.find_spec) rather than a ROOT-relative path, so this check
keeps working regardless of where autolycos is installed from. autolycos
checks its OWN invariants independently, from its own test file.
"""

from __future__ import annotations

import ast
import importlib.util
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
KERDOOS_SRC = ROOT / "packages" / "kerdoos" / "src" / "kerdoos"

TOOLS = {"requests", "curl_cffi", "playwright", "patchright",
         "playwright_stealth", "seleniumbase", "selenium", "bs4", "httpx",
         "yaml", "argon2", "mcp", "camoufox", "psutil"}

# Concrete adapter / wiring module suffixes that core must never import.
CONCRETE_SUFFIXES = ("adapters", "router", "factory",
                     "sqlite_store", "yaml_store")

# The consumer-facing contract listed in autolycos's README.
AUTOLYCOS_CONTRACT_MODULES = frozenset({
    "autolycos.ports", "autolycos.safety", "autolycos.errors",
    "autolycos.router", "autolycos.browser_gate", "autolycos.tiers",
})
DOCKERFILE = ROOT / "Dockerfile"


def _autolycos_src() -> pathlib.Path:
    spec = importlib.util.find_spec("autolycos")
    if spec is None or not spec.submodule_search_locations:
        raise AssertionError(
            "the autolycos package is not resolvable via importlib -- is "
            "it installed in this environment (uv sync --all-packages)?")
    return pathlib.Path(next(iter(spec.submodule_search_locations)))


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


def _autolycos_imports(source: str) -> list[tuple[str, str]]:
    """(module, imported name) for every autolycos import, read from the AST
    so a parenthesised multi-line import is seen whole. A plain
    `import autolycos.x` yields the module as its own name."""
    found: list[tuple[str, str]] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found.extend((alias.name, alias.name) for alias in node.names
                         if alias.name.split(".")[0] == "autolycos")
        elif (isinstance(node, ast.ImportFrom) and node.level == 0
              and node.module and node.module.split(".")[0] == "autolycos"):
            found.extend((node.module, alias.name) for alias in node.names)
    return found


def _dockerfile_snippets(text: str) -> list[str]:
    return re.findall(r'python3 -c\s*\\?\s*"([^"]*)"', text)


def _dockerfile_autolycos_imports(text: str) -> list[tuple[str, str]]:
    return [found for snippet in _dockerfile_snippets(text)
            for found in _autolycos_imports(snippet)]


def _dockerfile_unscanned_mentions(text: str) -> int:
    """autolycos mentions the snippet scan cannot see: another quoting,
    another interpreter name, a comment."""
    return text.count("autolycos.") - sum(
        snippet.count("autolycos.") for snippet in _dockerfile_snippets(text))


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
        autolycos_src = _autolycos_src()
        for f in _py_files(autolycos_src):
            for name in _imports(f):
                top = name.split(".")[0]
                self.assertNotIn(
                    top, ("core", "kerdoos"),
                    f"{f.relative_to(autolycos_src.parent)} imports {top!r} "
                    "(extractibility invariant: autolycos never imports "
                    "kerdoos/core)",
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
        autolycos_src = _autolycos_src()
        port_modules = [
            autolycos_src / "ports.py",
            autolycos_src / "errors.py",
            autolycos_src / "__init__.py",
            # safety.py is the shared anti-SSRF choke point imported by the
            # registry loader; it must stay tool-free (stdlib + .errors only)
            # so a future tool import in the SSRF guard breaks this test.
            autolycos_src / "safety.py",
            # challenge.py is the shared challenge heuristic imported by every
            # fetcher adapter; it must stay tool-free (pure stdlib) so the
            # cross-tier `challenged` signal never drags a tool in.
            autolycos_src / "challenge.py",
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
                    f"{f.name} (a core dependency) imports {name!r}",
                )

    def _assert_contract_import(self, where: str, module: str,
                                name: str) -> None:
        self.assertIn(
            module, AUTOLYCOS_CONTRACT_MODULES,
            f"{where} imports {module!r}, outside autolycos's contract")
        self.assertFalse(
            name.split(".")[-1].startswith("_"),
            f"{where} imports the private name {name!r} from {module!r}")

    def test_kerdoos_imports_only_the_autolycos_contract(self) -> None:
        for f in _py_files(KERDOOS_SRC):
            where = str(f.relative_to(ROOT))
            for module, name in _autolycos_imports(
                    f.read_text(encoding="utf-8")):
                self._assert_contract_import(where, module, name)

    def test_dockerfile_imports_only_the_autolycos_contract(self) -> None:
        imports = _dockerfile_autolycos_imports(
            DOCKERFILE.read_text(encoding="utf-8"))
        self.assertTrue(imports, "no autolycos import found in the Dockerfile")
        for module, name in imports:
            self._assert_contract_import("Dockerfile", module, name)

    def test_contract_scanners_see_every_import_form(self) -> None:
        source = "\n".join([
            "from autolycos.tiers import UC",
            "from autolycos.adapters.browser import (",
            "    NAV_TIMEOUT_MS,",
            ")",
            "import autolycos.adapters.uc",
        ])
        self.assertEqual(_autolycos_imports(source), [
            ("autolycos.tiers", "UC"),
            ("autolycos.adapters.browser", "NAV_TIMEOUT_MS"),
            ("autolycos.adapters.uc", "autolycos.adapters.uc"),
        ])
        dockerfile = "\n".join([
            "RUN X=$(python3 -c \\",
            '      "from autolycos.adapters.uc import _find as f; print(f())")',
        ])
        self.assertEqual(_dockerfile_autolycos_imports(dockerfile),
                         [("autolycos.adapters.uc", "_find")])

    def test_every_dockerfile_mention_sits_in_a_scanned_snippet(self) -> None:
        self.assertEqual(
            _dockerfile_unscanned_mentions(
                DOCKERFILE.read_text(encoding="utf-8")), 0,
            "an autolycos mention in the Dockerfile escapes the snippet scan")

    def test_coverage_guard_counts_an_unscanned_mention(self) -> None:
        for sample in (
            "RUN X=$(python3 -c 'from autolycos.adapters.uc import _find')",
            'RUN X=$(python -c "from autolycos.adapters.uc import _find")',
        ):
            with self.subTest(sample=sample):
                self.assertEqual(_dockerfile_unscanned_mentions(sample), 1)


if __name__ == "__main__":
    unittest.main()
