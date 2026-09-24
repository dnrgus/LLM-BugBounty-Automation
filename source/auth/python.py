from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

# P3.2-4 (roadmap v3.2.0 Source Intelligence): heuristic auth-guard
# recognition -- known decorator names from common libraries
# (flask_login, flask-jwt-extended, django/DRF-style names) plus a
# generic "looks auth-related" substring fallback, since a hand-rolled
# `@require_auth`/`@company_internal_auth` decorator is common and can't
# be enumerated exhaustively.
_KNOWN_AUTH_DECORATORS = {
    "login_required", "jwt_required", "auth_required", "require_auth",
    "requires_auth", "permission_required", "roles_required", "authenticated",
}
_AUTH_NAME_HINTS = ("auth", "login", "permission", "protected", "authorize", "current_user")


@dataclass(frozen=True)
class AuthGuardHint:
    """One route handler's auth-guard evidence -- deliberately a
    *candidate*, never a confirmed absence. `detected=False` means "no
    recognized guard pattern was found", not "this route has no auth":
    auth may be enforced by middleware, a framework-level default, or a
    decorator this heuristic doesn't recognize (roadmap's own stated
    risk: "'auth 없음'의 잘못된 단정 위험").
    """

    handler: str
    file: str
    line: int
    guard_names: list[str] = field(default_factory=list)
    detected: bool = False
    confidence: float = 0.3
    note: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "handler": self.handler,
            "file": self.file,
            "line": self.line,
            "guard_names": self.guard_names,
            "detected": self.detected,
            "confidence": self.confidence,
            "note": self.note,
        }


def find_auth_guards(path: Path, text: str, route_handlers: set[str]) -> list[AuthGuardHint]:
    """Checks each of `route_handlers` (route handler function names
    already identified by source/parsers/python.py) for a recognizable
    auth-guard decorator or FastAPI `Depends(...)` auth dependency.
    Functions that aren't in `route_handlers` are ignored -- this is
    about *routes'* auth posture, not every function in the file.
    """
    if not route_handlers:
        return []
    try:
        tree = ast.parse(text, filename=str(path))
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []

    hints: list[AuthGuardHint] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.name not in route_handlers:
            continue
        guard_names = sorted(
            {name for name in (_decorator_name(d) for d in node.decorator_list) if name and _is_auth_name(name)}
            | set(_fastapi_depends_auth_params(node))
        )
        detected = bool(guard_names)
        hints.append(
            AuthGuardHint(
                handler=node.name,
                file=str(path),
                line=node.lineno,
                guard_names=guard_names,
                detected=detected,
                confidence=0.65 if detected else 0.3,
                note=(
                    "auth guard decorator/dependency found -- verify it actually enforces auth at runtime, "
                    "not just that it's present"
                    if detected
                    else "no recognized auth guard pattern found -- NOT proof this route is unauthenticated "
                    "(could be enforced by middleware, a framework default, or an unrecognized decorator)"
                ),
            )
        )
    return hints


def _decorator_name(decorator: ast.expr) -> str | None:
    if isinstance(decorator, ast.Name):
        return decorator.id
    if isinstance(decorator, ast.Attribute):
        return decorator.attr
    if isinstance(decorator, ast.Call):
        return _decorator_name(decorator.func)
    return None


def _is_auth_name(name: str) -> bool:
    lowered = name.lower()
    if lowered in _KNOWN_AUTH_DECORATORS:
        return True
    return any(hint in lowered for hint in _AUTH_NAME_HINTS)


def _fastapi_depends_auth_params(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    names: list[str] = []
    for default in [*node.args.defaults, *node.args.kw_defaults]:
        if not isinstance(default, ast.Call):
            continue
        if _decorator_name(default.func) != "Depends" or not default.args:
            continue
        dependency = default.args[0]
        dep_name = dependency.id if isinstance(dependency, ast.Name) else None
        if dep_name and _is_auth_name(dep_name):
            names.append(dep_name)
    return names
