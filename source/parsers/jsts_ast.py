from __future__ import annotations

from pathlib import Path
from typing import Any

_language_cache: dict[str, Any] = {}


class TreeSitterUnavailable(RuntimeError):
    """Raised when a JS/TS/JSX/TSX file can't be parsed -- either the
    optional `jsts` extra isn't installed, or tree-sitter itself failed
    on this specific file. A caller never needs to know which."""


def parse_tree(path: Path, text: str) -> tuple[Any, bytes]:
    """P4.2-B (roadmap v4.2.0 Source Intelligence Expansion): the one
    place that loads a tree-sitter grammar for a JS/TS/JSX/TSX file and
    parses it, so source/parsers/javascript.py (routes/calls),
    source/frameworks/nestjs.py (P4.2-C), and source/dataflow/javascript.py
    + source/auth/javascript.py (P4.2-D) all reuse the exact same
    optional-dependency-safe parse step instead of re-implementing
    tree-sitter's language-loading logic independently.

    Optional dependency, same pattern as the browser adapter's
    Playwright dependency: importing this module always succeeds; this
    function raises TreeSitterUnavailable (never a raw ImportError or
    tree-sitter-specific exception a caller would need to know
    tree-sitter to catch) if the `jsts` extra isn't installed or the
    file can't be parsed, instead of raising something a caller could
    only handle by importing tree_sitter itself.
    """
    try:
        ts_language = _language_for(path.suffix.lower())
    except RuntimeError as exc:
        raise TreeSitterUnavailable(str(exc)) from exc

    from tree_sitter import Parser

    source_bytes = text.encode("utf-8", errors="ignore")
    try:
        tree = Parser(ts_language).parse(source_bytes)
    except Exception as exc:  # noqa: BLE001 -- never let a parser crash take down the whole audit
        raise TreeSitterUnavailable(f"{path}: {exc}") from exc
    return tree, source_bytes


def node_text(source: bytes, node: Any) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def dotted_call_name(node: Any, source: bytes) -> str | None:
    """P4.2-D: the JS/TS equivalent of source/dataflow/python.py's
    `_dotted_name` -- resolves a call's callee expression (identifier
    or member-expression chain) to a dotted string like "child_process.exec",
    matching source/sinks/python.py's sink_for_call's expected shape.
    """
    if node.type == "identifier":
        return node_text(source, node)
    if node.type == "member_expression":
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property")
        if obj is None or prop is None:
            return None
        base = dotted_call_name(obj, source)
        prop_name = node_text(source, prop)
        return f"{base}.{prop_name}" if base else prop_name
    return None


def _language_for(suffix: str) -> Any:
    try:
        from tree_sitter import Language
    except ImportError as exc:
        raise RuntimeError("tree-sitter is not installed (pip install '.[jsts]')") from exc

    if suffix in _language_cache:
        return _language_cache[suffix]

    if suffix == ".ts":
        import tree_sitter_typescript as tsts

        language = Language(tsts.language_typescript())
    elif suffix == ".tsx":
        import tree_sitter_typescript as tsts

        language = Language(tsts.language_tsx())
    else:  # .js / .jsx
        import tree_sitter_javascript as tsjs

        language = Language(tsjs.language())
    _language_cache[suffix] = language
    return language
