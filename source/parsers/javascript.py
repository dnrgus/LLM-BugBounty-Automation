from __future__ import annotations

from pathlib import Path
from typing import Any

from source.frameworks.express import is_express_route_call
from source.frameworks.nextjs import (
    app_router_route_path,
    is_app_router_route_file,
    is_pages_api_route,
    pages_api_route_path,
)
from source.models import CallNode, ParserResult, RouteNode

_NEXT_HTTP_EXPORT_NAMES = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

_language_cache: dict[str, Any] = {}


class JavaScriptTypeScriptParser:
    """P3.2-2 (roadmap v3.2.0 Source Intelligence): extracts Express
    routes, Next.js API routes (Pages Router and App Router), and raw
    call sites (fetch/db/exec candidates for later dataflow phases --
    see source/models.py's CallNode) from a JS/TS/JSX/TSX file via
    tree-sitter.

    Optional dependency, same pattern as the browser adapter's Playwright
    dependency: importing this module always succeeds; parse_file()
    reports a ParserResult error (triggering source/routes.py's per-file
    regex fallback) if the `jsts` extra (pip install '.[jsts]') isn't
    actually installed, instead of raising.
    """

    language = "javascript"

    def parse_file(self, path: Path, text: str) -> ParserResult:
        try:
            ts_language = _language_for(path.suffix.lower())
        except RuntimeError as exc:
            return ParserResult(language=self.language, errors=[str(exc)])

        from tree_sitter import Parser

        source_bytes = text.encode("utf-8", errors="ignore")
        try:
            tree = Parser(ts_language).parse(source_bytes)
        except Exception as exc:  # noqa: BLE001 -- never let a parser crash take down the whole audit
            return ParserResult(language=self.language, errors=[f"{path}: {exc}"])

        routes: list[RouteNode] = []
        calls: list[CallNode] = []
        _walk(tree.root_node, source_bytes, path, routes, calls, enclosing=None)
        routes.extend(_nextjs_routes(path, tree.root_node, source_bytes))
        return ParserResult(language=self.language, routes=routes, calls=calls)


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


def _text(source: bytes, node: Any) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _walk(node: Any, source: bytes, path: Path, routes: list[RouteNode], calls: list[CallNode], enclosing: str | None) -> None:
    next_enclosing = enclosing
    if node.type in {"function_declaration", "method_definition"}:
        name_node = node.child_by_field_name("name")
        if name_node is not None:
            next_enclosing = _text(source, name_node)

    if node.type == "call_expression":
        route = _express_route_from_call(node, source, path)
        if route is not None:
            routes.append(route)
        dotted = _dotted_callee(node, source)
        if dotted is not None:
            calls.append(
                CallNode(name=dotted, file=str(path), line=node.start_point[0] + 1, enclosing_function=enclosing)
            )

    for child in node.children:
        _walk(child, source, path, routes, calls, next_enclosing)


def _dotted_callee(call_node: Any, source: bytes) -> str | None:
    func = call_node.child_by_field_name("function")
    return _dotted_from_expr(func, source) if func is not None else None


def _dotted_from_expr(node: Any, source: bytes) -> str | None:
    if node.type == "identifier":
        return _text(source, node)
    if node.type == "member_expression":
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property")
        if obj is None or prop is None:
            return None
        base = _dotted_from_expr(obj, source)
        prop_name = _text(source, prop)
        return f"{base}.{prop_name}" if base else prop_name
    return None


def _express_route_from_call(call_node: Any, source: bytes, path: Path) -> RouteNode | None:
    func = call_node.child_by_field_name("function")
    if func is None or func.type != "member_expression":
        return None
    obj = func.child_by_field_name("object")
    prop = func.child_by_field_name("property")
    if obj is None or prop is None or obj.type != "identifier":
        return None
    object_name = _text(source, obj)
    method_name = _text(source, prop)
    if not is_express_route_call(object_name, method_name):
        return None

    args = call_node.child_by_field_name("arguments")
    if args is None or not args.named_children:
        return None
    route_path = _string_literal_value(args.named_children[0], source)
    if route_path is None:
        return None

    handler_name = _handler_name(args.named_children[-1], source) if len(args.named_children) > 1 else "anonymous"
    return RouteNode(
        method=method_name.upper(),
        path=route_path,
        handler=handler_name,
        file=str(path),
        line=call_node.start_point[0] + 1,
        framework="express",
    )


def _handler_name(node: Any, source: bytes) -> str:
    if node.type == "identifier":
        return _text(source, node)
    if node.type in {"function", "function_expression"}:
        name_node = node.child_by_field_name("name")
        if name_node is not None:
            return _text(source, name_node)
    return "anonymous"


def _string_literal_value(node: Any, source: bytes) -> str | None:
    if node.type != "string":
        return None
    for child in node.children:
        if child.type == "string_fragment":
            return _text(source, child)
    return None


def _nextjs_routes(path: Path, root_node: Any, source: bytes) -> list[RouteNode]:
    if is_pages_api_route(path):
        return [
            RouteNode(
                method="ANY",
                path=pages_api_route_path(path),
                handler="handler",
                file=str(path),
                line=1,
                framework="nextjs_pages_router",
            )
        ]
    if is_app_router_route_file(path):
        route_path = app_router_route_path(path)
        return [
            RouteNode(method=method, path=route_path, handler=name, file=str(path), line=line, framework="nextjs_app_router")
            for method, name, line in _exported_http_method_functions(root_node, source)
        ]
    return []


def _exported_http_method_functions(root_node: Any, source: bytes) -> list[tuple[str, str, int]]:
    results: list[tuple[str, str, int]] = []
    for child in root_node.children:
        if child.type != "export_statement":
            continue
        for grandchild in child.children:
            if grandchild.type != "function_declaration":
                continue
            name_node = grandchild.child_by_field_name("name")
            if name_node is None:
                continue
            name = _text(source, name_node)
            if name in _NEXT_HTTP_EXPORT_NAMES:
                results.append((name, name, grandchild.start_point[0] + 1))
    return results
