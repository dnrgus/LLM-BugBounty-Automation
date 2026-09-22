from __future__ import annotations

import ast

# P3.2-3 (roadmap v3.2.0 Source Intelligence): the same request attributes
# source/analyzers.py's regex input-detector already looks for
# (request.args/form/json/files/cookies/headers), reused here as the taint
# *origin* for dataflow tracing rather than a standalone match.
REQUEST_ATTRS = {"args", "form", "json", "files", "cookies", "headers"}
REQUEST_JSON_METHODS = {"get_json"}


def is_request_source_expression(node: ast.expr) -> bool:
    """True if `node` is (or is derived from, via attribute/subscript/call
    access) Flask/FastAPI's `request` object's user-controlled data --
    e.g. `request.args`, `request.args.get('x')`, `request.json['x']`,
    `request.get_json()`.
    """
    if isinstance(node, ast.Attribute):
        if node.attr in REQUEST_ATTRS and _is_request_name(node.value):
            return True
        return is_request_source_expression(node.value)
    if isinstance(node, ast.Subscript):
        return is_request_source_expression(node.value)
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in REQUEST_JSON_METHODS and _is_request_name(func.value):
            return True
        return is_request_source_expression(func)
    return False


def _is_request_name(node: ast.expr) -> bool:
    return isinstance(node, ast.Name) and node.id == "request"
