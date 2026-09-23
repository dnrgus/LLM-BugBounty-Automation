from __future__ import annotations

from pathlib import Path
from typing import Any

from source.frameworks.express import is_express_route_call
from source.frameworks.nestjs import http_method_for_decorator, is_controller_decorator, join_route_path
from source.frameworks.nextjs import (
    app_router_route_path,
    is_app_router_route_file,
    is_pages_api_route,
    pages_api_route_path,
)
from source.models import CallNode, ParserResult, RouteNode
from source.parsers.jsts_ast import TreeSitterUnavailable, parse_tree

_NEXT_HTTP_EXPORT_NAMES = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}


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
            tree, source_bytes = parse_tree(path, text)
        except TreeSitterUnavailable as exc:
            return ParserResult(language=self.language, errors=[str(exc)])

        routes: list[RouteNode] = []
        calls: list[CallNode] = []
        _walk(tree.root_node, source_bytes, path, routes, calls, enclosing=None)
        routes.extend(_nextjs_routes(path, tree.root_node, source_bytes))
        _find_nestjs_controller_routes(tree.root_node, source_bytes, path, routes)
        return ParserResult(language=self.language, routes=routes, calls=calls)


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


def _find_nestjs_controller_routes(node: Any, source: bytes, path: Path, routes: list[RouteNode]) -> None:
    """P4.2-C: NestJS decorators are siblings of their target, not
    children of it (a @Controller('cats') decorator and its
    `class CatsController` are both direct named children of the same
    export_statement/program node, with an unnamed `export` keyword
    token also sitting between them) -- so this walks each node's own
    `.named_children` in source order (skipping keyword/punctuation
    tokens, which would otherwise wrongly reset the pending list before
    the class is reached), accumulating decorator nodes until a
    class_declaration consumes them, and recurses into every named
    child either way to find controllers nested anywhere in the file.
    """
    pending_decorators: list[Any] = []
    for child in node.named_children:
        if child.type == "decorator":
            pending_decorators.append(child)
            continue
        if child.type == "class_declaration":
            prefix = _controller_prefix(pending_decorators, source)
            if prefix is not None:
                routes.extend(_nestjs_methods_for_class(child, prefix, source, path))
        pending_decorators = []
        _find_nestjs_controller_routes(child, source, path, routes)


def _decorator_call(decorator_node: Any) -> Any | None:
    for child in decorator_node.children:
        if child.type == "call_expression":
            return child
    return None


def _decorator_call_name(call_node: Any, source: bytes) -> str | None:
    name_node = call_node.child_by_field_name("function")
    return _text(source, name_node) if name_node is not None else None


def _decorator_call_first_string_arg(call_node: Any, source: bytes) -> str:
    args = call_node.child_by_field_name("arguments")
    if args is None or not args.named_children:
        return ""
    return _string_literal_value(args.named_children[0], source) or ""


def _controller_prefix(decorators: list[Any], source: bytes) -> str | None:
    for decorator in decorators:
        call = _decorator_call(decorator)
        if call is None:
            continue
        name = _decorator_call_name(call, source)
        if name is not None and is_controller_decorator(name):
            return _decorator_call_first_string_arg(call, source)
    return None


def _nestjs_methods_for_class(class_node: Any, prefix: str, source: bytes, path: Path) -> list[RouteNode]:
    routes: list[RouteNode] = []
    body = class_node.child_by_field_name("body")
    if body is None:
        return routes
    pending_decorators: list[Any] = []
    for child in body.named_children:
        if child.type == "decorator":
            pending_decorators.append(child)
            continue
        if child.type == "method_definition":
            route = _nestjs_route_from_method(child, pending_decorators, prefix, source, path)
            if route is not None:
                routes.append(route)
        pending_decorators = []
    return routes


def _nestjs_route_from_method(
    method_node: Any, decorators: list[Any], prefix: str, source: bytes, path: Path
) -> RouteNode | None:
    http_method: str | None = None
    method_path = ""
    for decorator in decorators:
        call = _decorator_call(decorator)
        if call is None:
            continue
        name = _decorator_call_name(call, source)
        mapped = http_method_for_decorator(name) if name is not None else None
        if mapped is not None:
            http_method = mapped
            method_path = _decorator_call_first_string_arg(call, source)
    if http_method is None:
        return None
    name_node = method_node.child_by_field_name("name")
    handler_name = _text(source, name_node) if name_node is not None else "anonymous"
    return RouteNode(
        method=http_method,
        path=join_route_path(prefix, method_path),
        handler=handler_name,
        file=str(path),
        line=method_node.start_point[0] + 1,
        framework="nestjs",
    )
