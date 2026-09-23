"""P4.2-B JS/TS tree-sitter AST adapter (roadmap v4.2.0 Source
Intelligence Expansion): the shared parse_tree() helper other JS/TS
analyzers (frameworks, dataflow, auth) reuse instead of each
reimplementing tree-sitter's language-loading logic.
"""

from pathlib import Path

import pytest

tree_sitter = pytest.importorskip("tree_sitter")

from source.parsers.jsts_ast import parse_tree  # noqa: E402


def test_parse_tree_returns_a_root_node_and_source_bytes() -> None:
    tree, source_bytes = parse_tree(Path("app.js"), "const x = 1;")
    assert tree.root_node is not None
    assert source_bytes == b"const x = 1;"


def test_parse_tree_handles_typescript_suffix() -> None:
    tree, source_bytes = parse_tree(Path("app.ts"), "const x: number = 1;")
    assert tree.root_node is not None


def test_parse_tree_handles_tsx_suffix() -> None:
    tree, source_bytes = parse_tree(Path("app.tsx"), "const x = <div />;")
    assert tree.root_node is not None


def test_parse_tree_caches_the_language_per_suffix() -> None:
    from source.parsers import jsts_ast

    jsts_ast._language_cache.clear()
    parse_tree(Path("a.js"), "1;")
    assert ".js" in jsts_ast._language_cache
    parse_tree(Path("b.js"), "2;")
    assert len(jsts_ast._language_cache) == 1
