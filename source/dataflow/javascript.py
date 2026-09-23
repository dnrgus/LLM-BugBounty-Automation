from __future__ import annotations

from pathlib import Path
from typing import Any

from source.models import DataEdge
from source.parsers.jsts_ast import TreeSitterUnavailable, dotted_call_name, node_text, parse_tree
from source.sinks.python import sink_for_call
from source.sources.javascript import is_request_source_expression

_FUNCTION_LIKE_TYPES = {"function_declaration", "function_expression", "arrow_function", "method_definition"}


def trace_dataflow(path: Path, text: str) -> list[DataEdge]:
    """P4.2-D (roadmap v4.2.0 Source Intelligence Expansion): the JS/TS
    equivalent of source/dataflow/python.py's trace_dataflow -- function-
    local taint tracking from Express/NestJS request access
    (source/sources/javascript.py) to a known dangerous call
    (source/sinks/python.py's sink_for_call, extended with JS-specific
    dotted names).

    Deliberately narrower than the Python tracer, matching its own
    "lightweight" framing but drawing the line earlier for v1:
    single-scope only -- no 1-hop interprocedural propagation across
    function boundaries (a tainted value passed into another
    same-file function is not tracked). Each function-like body (and
    the module top level) is analyzed independently. Control-flow
    blocks are not flattened into one pass the way the Python tracer
    does; instead every non-function descendant of a scope is visited
    in tree-sitter's own document order, which is precise enough for
    typical straight-line handler bodies.
    """
    try:
        tree, source_bytes = parse_tree(path, text)
    except TreeSitterUnavailable:
        return []

    edges: list[DataEdge] = []
    _analyze_scope(tree.root_node, source_bytes, path, edges)
    for func_node in _function_like_nodes(tree.root_node):
        body = func_node.child_by_field_name("body")
        if body is not None:
            _analyze_scope(body, source_bytes, path, edges)

    seen: set[tuple[str, str, str, int]] = set()
    deduped: list[DataEdge] = []
    for edge in edges:
        key = (edge.source, edge.sink, edge.file, edge.line)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(edge)
    return deduped


def _function_like_nodes(node: Any) -> list[Any]:
    found: list[Any] = []
    for child in node.children:
        if child.type in _FUNCTION_LIKE_TYPES:
            found.append(child)
        found.extend(_function_like_nodes(child))
    return found


def _descendants_excluding_nested_functions(node: Any) -> list[Any]:
    """A scope's own statements, flattened -- but stops descending the
    moment it reaches a nested function-like node (that node is still
    yielded once, as a leaf, so trace_dataflow's own top-level scan can
    find and independently analyze it; its *contents* are never walked
    from here, so a call inside a nested callback is never analyzed
    against the outer scope's taint set)."""
    result: list[Any] = []
    for child in node.children:
        result.append(child)
        if child.type not in _FUNCTION_LIKE_TYPES:
            result.extend(_descendants_excluding_nested_functions(child))
    return result


def _analyze_scope(scope_node: Any, source: bytes, path: Path, edges: list[DataEdge]) -> None:
    tainted: set[str] = set()
    for node in _descendants_excluding_nested_functions(scope_node):
        if node.type == "call_expression":
            func = node.child_by_field_name("function")
            dotted = dotted_call_name(func, source) if func is not None else None
            if dotted is not None:
                sink = sink_for_call(dotted)
                if sink is not None and _call_has_tainted_arg(node, tainted, source):
                    edges.append(DataEdge(source="request", sink=sink, file=str(path), line=node.start_point[0] + 1))
        elif node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")
            if name_node is None or name_node.type != "identifier":
                continue
            name = node_text(source, name_node)
            if value_node is not None and _expr_taint(value_node, tainted, source):
                tainted.add(name)
            else:
                tainted.discard(name)
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is None or left.type != "identifier" or right is None:
                continue
            name = node_text(source, left)
            if _expr_taint(right, tainted, source):
                tainted.add(name)
            else:
                tainted.discard(name)


def _call_has_tainted_arg(call_node: Any, tainted: set[str], source: bytes) -> bool:
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return False
    return any(_expr_taint(arg, tainted, source) for arg in args.named_children)


def _expr_taint(node: Any, tainted: set[str], source: bytes) -> bool:
    if is_request_source_expression(node, source):
        return True
    if node.type == "identifier":
        return node_text(source, node) in tainted
    if node.type in {"member_expression", "subscript_expression"}:
        obj = node.child_by_field_name("object")
        return obj is not None and _expr_taint(obj, tainted, source)
    if node.type == "call_expression":
        func = node.child_by_field_name("function")
        if func is not None and _expr_taint(func, tainted, source):
            return True
        return _call_has_tainted_arg(node, tainted, source)
    if node.type == "binary_expression":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        return (left is not None and _expr_taint(left, tainted, source)) or (
            right is not None and _expr_taint(right, tainted, source)
        )
    if node.type == "template_string":
        for child in node.named_children:
            if child.type == "template_substitution" and child.named_children:
                if _expr_taint(child.named_children[0], tainted, source):
                    return True
        return False
    if node.type in {"array", "object"}:
        return any(_expr_taint(child, tainted, source) for child in node.named_children)
    if node.type == "pair":
        value = node.child_by_field_name("value")
        return value is not None and _expr_taint(value, tainted, source)
    if node.type == "parenthesized_expression" and node.named_children:
        return _expr_taint(node.named_children[0], tainted, source)
    return False
