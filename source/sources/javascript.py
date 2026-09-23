from __future__ import annotations

from typing import Any

# P4.2-D (roadmap v4.2.0 Source Intelligence Expansion): Express/NestJS's
# request-object member expressions -- the JS/TS equivalent of
# source/sources/python.py's Flask/FastAPI `request.*` recognition.
REQUEST_MEMBER_NAMES = {"query", "body", "params", "cookies", "headers"}
REQUEST_OBJECT_NAMES = {"req", "request"}


def is_request_source_expression(node: Any, source: bytes) -> bool:
    """True if `node` is (or is derived from, via member/subscript/call
    access) Express/NestJS's `req`/`request` object's user-controlled
    data -- e.g. `req.query`, `req.body.name`, `req.params['id']`.
    """
    if node.type == "member_expression":
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property")
        if obj is not None and prop is not None and _text(source, prop) in REQUEST_MEMBER_NAMES and _is_request_name(obj, source):
            return True
        return obj is not None and is_request_source_expression(obj, source)
    if node.type == "subscript_expression":
        obj = node.child_by_field_name("object")
        return obj is not None and is_request_source_expression(obj, source)
    if node.type == "call_expression":
        func = node.child_by_field_name("function")
        return func is not None and is_request_source_expression(func, source)
    return False


def _is_request_name(node: Any, source: bytes) -> bool:
    return node.type == "identifier" and _text(source, node) in REQUEST_OBJECT_NAMES


def _text(source: bytes, node: Any) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
