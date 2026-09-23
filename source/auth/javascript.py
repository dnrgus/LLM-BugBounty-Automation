from __future__ import annotations

from pathlib import Path
from typing import Any

from source.auth.python import AuthGuardHint
from source.parsers.jsts_ast import TreeSitterUnavailable, dotted_call_name, node_text, parse_tree

# P4.2-D (roadmap v4.2.0 Source Intelligence Expansion): NestJS's
# @UseGuards(...) decorator -- the JS/TS equivalent of Python's
# decorator-name/FastAPI-Depends() heuristic in source/auth/python.py.
# Unlike Python's heuristic (any decorator whose *name* merely looks
# auth-related), @UseGuards(...) is NestJS's one definitive auth-guard
# mechanism -- its presence is a real framework construct, not a name
# guess, so this reports a slightly higher confidence when detected.
_USE_GUARDS_DECORATOR = "UseGuards"


def find_auth_guards(path: Path, text: str, route_handlers: set[str]) -> list[AuthGuardHint]:
    """Checks each of `route_handlers` (route handler method names
    already identified by source/parsers/javascript.py's NestJS route
    extraction) for a `@UseGuards(...)` decorator. Methods not in
    `route_handlers` are ignored -- this is about *routes'* auth
    posture, not every method in the file.
    """
    if not route_handlers:
        return []
    try:
        tree, source_bytes = parse_tree(path, text)
    except TreeSitterUnavailable:
        return []

    hints: list[AuthGuardHint] = []
    _find_methods_with_guards(tree.root_node, source_bytes, path, route_handlers, hints)
    return hints


def _find_methods_with_guards(
    node: Any, source: bytes, path: Path, route_handlers: set[str], hints: list[AuthGuardHint]
) -> None:
    pending_decorators: list[Any] = []
    for child in node.named_children:
        if child.type == "decorator":
            pending_decorators.append(child)
            continue
        if child.type == "method_definition":
            name_node = child.child_by_field_name("name")
            handler_name = node_text(source, name_node) if name_node is not None else None
            if handler_name is not None and handler_name in route_handlers:
                guard_names = _guard_names(pending_decorators, source)
                detected = bool(guard_names)
                hints.append(
                    AuthGuardHint(
                        handler=handler_name,
                        file=str(path),
                        line=child.start_point[0] + 1,
                        guard_names=sorted(guard_names),
                        detected=detected,
                        confidence=0.7 if detected else 0.3,
                        note=(
                            "@UseGuards(...) found -- verify it actually enforces auth at runtime, not just that "
                            "it's present"
                            if detected
                            else "no @UseGuards(...) found on this handler -- NOT proof this route is "
                            "unauthenticated (could be enforced by a global/module-level guard, middleware, or a "
                            "base class this static check can't see)"
                        ),
                    )
                )
        pending_decorators = []
        _find_methods_with_guards(child, source, path, route_handlers, hints)


def _guard_names(decorators: list[Any], source: bytes) -> set[str]:
    names: set[str] = set()
    for decorator in decorators:
        call = _decorator_call(decorator)
        if call is None:
            continue
        callee = call.child_by_field_name("function")
        callee_name = dotted_call_name(callee, source) if callee is not None else None
        if callee_name != _USE_GUARDS_DECORATOR:
            continue
        args = call.child_by_field_name("arguments")
        if args is None:
            continue
        for arg in args.named_children:
            if arg.type == "identifier":
                names.add(node_text(source, arg))
    return names


def _decorator_call(decorator_node: Any) -> Any | None:
    for child in decorator_node.children:
        if child.type == "call_expression":
            return child
    return None
