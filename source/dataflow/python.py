from __future__ import annotations

import ast
from pathlib import Path

from source.models import DataEdge
from source.sinks.python import sink_for_call
from source.sources.python import is_request_source_expression

_FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


def trace_dataflow(path: Path, text: str) -> list[DataEdge]:
    """P3.2-3 (roadmap v3.2.0 Source Intelligence): lightweight source ->
    sink dataflow tracing for one Python file -- real evidence (which
    request-derived value reaches which dangerous call, and where) rather
    than source/analyzers.py's independent, unconnected input/sink regex
    matches.

    Scope, deliberately bounded ("lightweight", per the roadmap):
    - Function-local taint tracking, processing each function's
      statements in a flattened top-to-bottom order (not a real
      control-flow graph -- loops/branches are all visited once in
      document order, which is precise enough for typical straight-line
      request handlers but can mis-order more complex control flow).
    - One-hop interprocedural: if a locally tainted value is passed as
      an argument to another function *defined in the same file*, that
      function's corresponding parameter is treated as tainted when
      re-analyzing it. This does not chase a taint chain through more
      than one call hop, and does not resolve aliasing, decorators that
      wrap the callee, or calls into other files/modules.

    A SyntaxError is swallowed (returns no edges for that file) rather
    than raised -- source/audit.py's SOURCE MODE already has a
    structural-parse fallback for Python (P3.2-1's PythonASTParser); a
    file that can't even ast.parse() simply contributes no dataflow
    edges, the same way it contributes no AST-derived routes.
    """
    try:
        tree = ast.parse(text, filename=str(path))
    except (SyntaxError, ValueError):
        return []

    functions: dict[str, _FunctionNode] = {
        node.name: node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    edges: list[DataEdge] = []
    propagated: dict[str, set[int]] = {}

    # The module's own top-level body is analyzed as one more scope, on
    # equal footing with each function -- some routing/setup code runs at
    # module level rather than inside a function.
    module_edges, module_propagated = _analyze_block(tree.body, path, initially_tainted=set())
    edges.extend(module_edges)
    for callee, positions in module_propagated.items():
        propagated.setdefault(callee, set()).update(positions)

    for func in functions.values():
        func_edges, func_propagated = _analyze_block(func.body, path, initially_tainted=set())
        edges.extend(func_edges)
        for callee, positions in func_propagated.items():
            propagated.setdefault(callee, set()).update(positions)

    for callee_name, positions in propagated.items():
        func = functions.get(callee_name)
        if func is None:
            continue
        param_names = [arg.arg for arg in func.args.args]
        initially_tainted = {param_names[i] for i in positions if i < len(param_names)}
        if not initially_tainted:
            continue
        extra_edges, _ = _analyze_block(func.body, path, initially_tainted)
        edges.extend(extra_edges)

    seen: set[tuple[str, str, str, int]] = set()
    deduped: list[DataEdge] = []
    for edge in edges:
        key = (edge.source, edge.sink, edge.file, edge.line)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(edge)
    return deduped


def _analyze_block(
    stmts: list[ast.stmt], path: Path, initially_tainted: set[str]
) -> tuple[list[DataEdge], dict[str, set[int]]]:
    tainted = set(initially_tainted)
    edges: list[DataEdge] = []
    propagated: dict[str, set[int]] = {}

    for stmt in _flatten(stmts):
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue  # nested functions get their own independent scope/pass
        for call in ast.walk(stmt):
            if not isinstance(call, ast.Call):
                continue
            dotted = _dotted_name(call.func)
            if dotted is None:
                continue
            sink = sink_for_call(dotted)
            if sink is not None:
                if _call_has_tainted_arg(call, tainted):
                    edges.append(DataEdge(source="request", sink=sink, file=str(path), line=call.lineno))
            else:
                positions = {i for i, arg in enumerate(call.args) if _expr_taint(arg, tainted)}
                if positions:
                    propagated.setdefault(dotted, set()).update(positions)

        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            target_name = stmt.targets[0].id
            if _expr_taint(stmt.value, tainted):
                tainted.add(target_name)
            else:
                tainted.discard(target_name)

    return edges, propagated


def _flatten(stmts: list[ast.stmt]) -> list[ast.stmt]:
    """Flattens if/for/while/try/with blocks into one top-to-bottom
    statement sequence -- not a real CFG (see trace_dataflow's
    docstring), just enough structure to walk a typical handler body in
    source order."""
    flat: list[ast.stmt] = []
    for stmt in stmts:
        flat.append(stmt)
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue  # analyzed separately as its own scope, not inlined here
        for attr in ("body", "orelse", "finalbody"):
            block = getattr(stmt, attr, None)
            if isinstance(block, list) and block and isinstance(block[0], ast.stmt):
                flat.extend(_flatten(block))
        handlers = getattr(stmt, "handlers", None)
        if isinstance(handlers, list):
            for handler in handlers:
                flat.extend(_flatten(handler.body))
    return flat


def _call_has_tainted_arg(call: ast.Call, tainted: set[str]) -> bool:
    if any(_expr_taint(arg, tainted) for arg in call.args):
        return True
    return any(_expr_taint(keyword.value, tainted) for keyword in call.keywords)


def _expr_taint(node: ast.expr, tainted: set[str]) -> bool:
    if is_request_source_expression(node):
        return True
    if isinstance(node, ast.Name):
        return node.id in tainted
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        return _expr_taint(node.value, tainted)
    if isinstance(node, ast.Call):
        if _expr_taint(node.func, tainted):
            return True
        return any(_expr_taint(arg, tainted) for arg in node.args) or any(
            _expr_taint(keyword.value, tainted) for keyword in node.keywords
        )
    if isinstance(node, ast.BinOp):
        return _expr_taint(node.left, tainted) or _expr_taint(node.right, tainted)
    if isinstance(node, ast.JoinedStr):
        return any(
            _expr_taint(value.value, tainted) for value in node.values if isinstance(value, ast.FormattedValue)
        )
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        # Covers the common LLM SDK call shape `messages=[{"role": "user",
        # "content": tainted_value}]` -- a literal container carries taint
        # if anything nested inside it does.
        return any(_expr_taint(elt, tainted) for elt in node.elts)
    if isinstance(node, ast.Dict):
        return any(_expr_taint(value, tainted) for value in node.values if value is not None)
    return False


def _dotted_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None
