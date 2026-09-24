from __future__ import annotations

import ast
from pathlib import Path

from source.models import CallNode, ParserResult, RouteNode

# Both Flask's @app.route(...)/@app.get(...) and FastAPI's @app.get(...)/
# @router.post(...)/@app.api_route(...) share this decorator shape closely
# enough to extract with one visitor -- "route"/"api_route" need their
# methods=[...] kwarg inspected, the rest (get/post/put/delete/patch) name
# the HTTP method directly.
_METHOD_DECORATORS = {"get", "post", "put", "delete", "patch"}
_GENERIC_ROUTE_DECORATORS = {"route", "api_route"}


class PythonASTParser:
    """P3.2-1 (roadmap v3.2.0 Source Intelligence): extracts Flask/FastAPI
    routes and raw call sites from a Python file using the standard
    library `ast` module -- "구조 이해" instead of source/routes.py's
    original regex pattern matching.

    A SyntaxError (e.g. a file this project doesn't fully support, or a
    genuinely malformed file) is caught and reported as a ParserResult
    error rather than raised, so a caller can fall back to the regex
    extractor for that one file (roadmap v3.2 gate: "AST 실패시 기존
    pattern analyzer fallback") instead of the whole audit failing.
    """

    language = "python"

    def parse_file(self, path: Path, text: str) -> ParserResult:
        try:
            tree = ast.parse(text, filename=str(path))
        except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
            return ParserResult(language=self.language, errors=[f"{path}: {exc}"])

        visitor = _RouteAndCallVisitor(path)
        visitor.visit(tree)
        return ParserResult(language=self.language, routes=visitor.routes, calls=visitor.calls)


class _RouteAndCallVisitor(ast.NodeVisitor):
    def __init__(self, path: Path) -> None:
        self._path = path
        self._function_stack: list[str] = []
        self.routes: list[RouteNode] = []
        self.calls: list[CallNode] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            route = _route_from_decorator(decorator, node.name, self._path)
            if route is not None:
                self.routes.append(route)
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        name = _dotted_name(node.func)
        if name is not None:
            self.calls.append(
                CallNode(
                    name=name,
                    file=str(self._path),
                    line=node.lineno,
                    enclosing_function=self._function_stack[-1] if self._function_stack else None,
                )
            )
        self.generic_visit(node)


def _dotted_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _route_from_decorator(decorator: ast.expr, handler_name: str, path: Path) -> RouteNode | None:
    if not isinstance(decorator, ast.Call):
        return None
    dotted = _dotted_name(decorator.func)
    if dotted is None:
        return None
    attr = dotted.rsplit(".", 1)[-1]
    if attr not in _METHOD_DECORATORS and attr not in _GENERIC_ROUTE_DECORATORS:
        return None
    if not decorator.args or not _is_str_constant(decorator.args[0]):
        return None
    route_path = decorator.args[0].value

    if attr in _METHOD_DECORATORS:
        method = attr.upper()
    else:
        method = _methods_from_kwargs(decorator) or "ROUTE"

    return RouteNode(
        method=method,
        path=route_path,
        handler=handler_name,
        file=str(path),
        line=decorator.lineno,
        framework="flask_fastapi",
    )


def _methods_from_kwargs(decorator: ast.Call) -> str | None:
    for keyword in decorator.keywords:
        if keyword.arg != "methods" or not isinstance(keyword.value, (ast.List, ast.Tuple)):
            continue
        methods = [elt.value.upper() for elt in keyword.value.elts if _is_str_constant(elt)]
        if methods:
            return "|".join(methods)
    return None


def _is_str_constant(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)
