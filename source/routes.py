from __future__ import annotations

import re

from attack_surface.models import AttackSurfaceItem
from source.ingestion import SourceFile

# Pattern-based, not AST-based (design doc section 8's "초기 범위"): high
# precision on the common decorator/call shapes, not a full parser. Flask's
# @app.route(...) doesn't encode the HTTP method in the decorator name
# itself (it's the methods=[...] kwarg), so that one case reports method
# "ROUTE" rather than guessing -- still locates the endpoint precisely.
_FASTAPI_FLASK_ROUTE = re.compile(r'@(?:\w+)\.(get|post|put|delete|patch|route)\(\s*["\']([^"\']+)["\']')
_EXPRESS_ROUTE = re.compile(r'(?:app|router)\.(get|post|put|delete|patch)\(\s*["\']([^"\']+)["\']')
_DJANGO_PATH = re.compile(r'\bpath\(\s*r?["\']([^"\']*)["\']')

_ROUTE_LANGUAGES = {"python", "javascript", "typescript"}


def extract_routes(files: list[SourceFile]) -> list[AttackSurfaceItem]:
    items: list[AttackSurfaceItem] = []
    for source_file in files:
        if source_file.language not in _ROUTE_LANGUAGES:
            continue
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
        items.append(_route_item(source_file, text, match.start(), method, path, "flask_fastapi"))
    for match in _EXPRESS_ROUTE.finditer(text):
        method_token, path = match.groups()
        items.append(_route_item(source_file, text, match.start(), method_token.upper(), path, "express"))
    for match in _DJANGO_PATH.finditer(text):
        (path,) = match.groups()
        if not path:
            continue
        items.append(_route_item(source_file, text, match.start(), "ANY", path, "django"))
    return items


def _route_item(source_file: SourceFile, text: str, offset: int, method: str, path: str, framework: str) -> AttackSurfaceItem:
    line = text.count("\n", 0, offset) + 1
    location = path if path.startswith("/") else f"/{path}"
    return AttackSurfaceItem(
        source_type="source",
        asset_type="endpoint",
        location=location,
        metadata={"method": method, "framework": framework, "file": str(source_file.path), "line": line},
        confidence=0.6,
        evidence_refs=[f"{source_file.path}:{line}"],
        correlation_keys=[f"{method}:{location}"],
    )
