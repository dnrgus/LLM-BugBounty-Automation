from __future__ import annotations

import re

from attack_surface.models import AttackSurfaceItem
from source.ingestion import SourceFile
from source.models import RouteNode
from source.parsers.javascript import JavaScriptTypeScriptParser
from source.parsers.python import PythonASTParser

# Pattern-based, not AST-based (design doc section 8's "초기 범위"): high
# precision on the common decorator/call shapes, not a full parser. Flask's
# @app.route(...) doesn't encode the HTTP method in the decorator name
# itself (it's the methods=[...] kwarg), so that one case reports method
# "ROUTE" rather than guessing -- still locates the endpoint precisely.
_FASTAPI_FLASK_ROUTE = re.compile(r'@(?:\w+)\.(get|post|put|delete|patch|route)\(\s*["\']([^"\']+)["\']')
# (?<!@) keeps this from also matching a Python @app.get(...)/@app.post(...)
# decorator -- without it, an explicit-method Flask/FastAPI decorator (unlike
# the generic @app.route(...) form) is a substring match for both patterns,
# double-counting one real route as two with different "framework" tags.
_EXPRESS_ROUTE = re.compile(r'(?<!@)(?:app|router)\.(get|post|put|delete|patch)\(\s*["\']([^"\']+)["\']')
_DJANGO_PATH = re.compile(r'\bpath\(\s*r?["\']([^"\']*)["\']')

_ROUTE_LANGUAGES = {"python", "javascript", "typescript"}

_js_ts_ast_parser = JavaScriptTypeScriptParser()
_AST_PARSERS = {
    "python": PythonASTParser(),
    "javascript": _js_ts_ast_parser,
    "typescript": _js_ts_ast_parser,
}


def extract_routes(files: list[SourceFile]) -> list[AttackSurfaceItem]:
    """P3.2-1/P3.2-2 (roadmap v3.2.0 Source Intelligence): every route
    language has an AST parser (source/parsers/python.py,
    source/parsers/javascript.py) tried first -- "구조 이해" instead of
    pattern matching. A file the parser can't handle
    (ParserResult.errors non-empty -- a genuine SyntaxError, or, for
    JS/TS, tree-sitter's optional `jsts` extra not being installed)
    falls back to this module's original regex extractor for *that file
    only*, so one bad file or a missing optional dependency degrades
    gracefully instead of losing route coverage for the whole tree.
    """
    items: list[AttackSurfaceItem] = []
    regex_fallback_files: list[SourceFile] = []

    for source_file in files:
        if source_file.language not in _ROUTE_LANGUAGES:
            continue
        try:
            text = source_file.path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        parser = _AST_PARSERS.get(source_file.language)
        try:
            result = parser.parse_file(source_file.path, text)
        except (RecursionError, MemoryError):
            regex_fallback_files.append(source_file)  # P4.7 WP-08: degrade, never abort
            continue
        if result.errors:
            regex_fallback_files.append(source_file)
        else:
            items.extend(_ast_route_item(source_file, route) for route in result.routes)

    for source_file in regex_fallback_files:
        try:
            text = source_file.path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        items.extend(_extract_from_text(source_file, text))

    return items


def _extract_from_text(source_file: SourceFile, text: str) -> list[AttackSurfaceItem]:
    items: list[AttackSurfaceItem] = []
    for match in _FASTAPI_FLASK_ROUTE.finditer(text):
        method_token, path = match.groups()
        method = "ROUTE" if method_token == "route" else method_token.upper()
        line = text.count("\n", 0, match.start()) + 1
        items.append(_route_item(source_file, line, method, path, "flask_fastapi", extraction="pattern"))
    for match in _EXPRESS_ROUTE.finditer(text):
        method_token, path = match.groups()
        line = text.count("\n", 0, match.start()) + 1
        items.append(_route_item(source_file, line, method_token.upper(), path, "express", extraction="pattern"))
    for match in _DJANGO_PATH.finditer(text):
        (path,) = match.groups()
        if not path:
            continue
        line = text.count("\n", 0, match.start()) + 1
        items.append(_route_item(source_file, line, "ANY", path, "django", extraction="pattern"))
    return items


def _ast_route_item(source_file: SourceFile, route: RouteNode) -> AttackSurfaceItem:
    return _route_item(
        source_file, route.line, route.method, route.path, route.framework,
        extraction="ast", handler=route.handler,
    )


def _route_item(
    source_file: SourceFile,
    line: int,
    method: str,
    path: str,
    framework: str,
    extraction: str = "pattern",
    handler: str | None = None,
) -> AttackSurfaceItem:
    location = path if path.startswith("/") else f"/{path}"
    metadata: dict[str, object] = {
        "method": method,
        "framework": framework,
        "file": str(source_file.path),
        "line": line,
        "extraction": extraction,
    }
    if handler is not None:
        metadata["handler"] = handler
    return AttackSurfaceItem(
        source_type="source",
        asset_type="endpoint",
        location=location,
        # AST-derived routes carry a real parsed method/path/handler
        # (not a pattern match that could be a false positive in a
        # comment/string), so they get a higher base confidence.
        metadata=metadata,
        confidence=0.75 if extraction == "ast" else 0.6,
        evidence_refs=[f"{source_file.path}:{line}"],
        correlation_keys=[f"{method}:{location}"],
    )
