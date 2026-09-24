from __future__ import annotations

import ast
import time
from dataclasses import dataclass, field
from pathlib import Path

from source.sinks.python import sink_family, sink_for_call
from source.sources.python import is_request_source_expression

# P4.6 WP-04 (v5.0 plan 6.1): project-wide Python interprocedural dataflow.
# source/dataflow/python.py stays the per-file, 1-hop tracer; this module
# adds route -> helper/service -> sink chains across files, N hops deep.
#
# Resolution scope (deliberately bounded, documented as a limitation):
# - module-level functions in the analyzed tree, called by bare name
#   (same file or `from pkg.mod import f [as g]`) or as `mod.f` after
#   `import pkg.mod as mod` / `from pkg import mod`;
# - class methods are NOT resolved (no receiver type inference) --
#   `self.repo.find(x)` is a cut, not a guess.
# Caps: max_depth hops, max_nodes function analyses, time_budget_s wall
# clock. Hitting any cap stops expansion gracefully and is reported in
# InterproceduralStats.truncated, never raised.

DEFAULT_MAX_DEPTH = 4
DEFAULT_MAX_NODES = 500
DEFAULT_TIME_BUDGET_S = 5.0

_FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef
_ROUTE_DECORATORS = {"get", "post", "put", "delete", "patch", "route", "api_route"}


@dataclass(frozen=True)
class FunctionInfo:
    qualname: str  # "pkg.mod:func"
    module: str
    name: str
    file: str
    node: _FunctionNode
    params: list[str]
    is_route: bool
    depends_params: frozenset[str] = frozenset()


@dataclass(frozen=True)
class InterproceduralEdge:
    source: str  # "request": request.* data or a route handler parameter
    sink: str
    sink_family: str
    file: str
    line: int
    entry: str  # qualname of the route handler the chain starts at
    call_path: tuple[str, ...]  # entry ... function containing the sink

    @property
    def hops(self) -> int:
        return len(self.call_path) - 1

    def to_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "sink": self.sink,
            "sink_family": self.sink_family,
            "file": self.file,
            "line": self.line,
            "entry": self.entry,
            "call_path": list(self.call_path),
            "hops": self.hops,
        }


@dataclass
class InterproceduralStats:
    functions: int = 0
    analyses: int = 0
    max_depth_reached: int = 0
    truncated: list[str] = field(default_factory=list)
    elapsed_s: float = 0.0

    def to_dict(self) -> dict[str, object]:
        return {
            "functions": self.functions,
            "analyses": self.analyses,
            "max_depth_reached": self.max_depth_reached,
            "truncated": sorted(set(self.truncated)),
            "elapsed_s": round(self.elapsed_s, 3),
        }


def _module_name(root: Path, file: Path) -> str:
    try:
        relative = file.resolve().relative_to(root.resolve())
    except ValueError:
        relative = Path(file.name)
    parts = list(relative.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) or file.stem


def _dotted(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _is_route(func: _FunctionNode) -> bool:
    for decorator in func.decorator_list:
        if isinstance(decorator, ast.Call):
            name = _dotted(decorator.func)
            if name and "." in name and name.rsplit(".", 1)[1] in _ROUTE_DECORATORS:
                return True
    return False


def _depends_params(func: _FunctionNode) -> frozenset[str]:
    args = func.args.args
    defaults = [None] * (len(args) - len(func.args.defaults)) + list(func.args.defaults)
    names = set()
    for arg, default in zip(args, defaults):
        if isinstance(default, ast.Call) and _dotted(default.func) in {"Depends", "fastapi.Depends"}:
            names.add(arg.arg)
    return frozenset(names)


class ProjectIndex:
    def __init__(self, root: Path, files: list[Path]):
        self.root = root
        self.functions: dict[str, FunctionInfo] = {}
        # per module: local name -> qualname (functions) / module name (modules)
        self._func_aliases: dict[str, dict[str, str]] = {}
        self._module_aliases: dict[str, dict[str, str]] = {}
        trees: dict[str, tuple[Path, ast.Module]] = {}
        for file in files:
            try:
                tree = ast.parse(file.read_text(encoding="utf-8", errors="ignore"), filename=str(file))
            except (SyntaxError, ValueError, OSError, RecursionError, MemoryError):
                continue
            trees[_module_name(root, file)] = (file, tree)

        for module, (file, tree) in trees.items():
            aliases: dict[str, str] = {}
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    qualname = f"{module}:{node.name}"
                    self.functions[qualname] = FunctionInfo(
                        qualname, module, node.name, str(file), node, [a.arg for a in node.args.args],
                        _is_route(node), _depends_params(node),
                    )
                    aliases[node.name] = qualname
            self._func_aliases[module] = aliases

        module_names = set(trees)
        for module, (_file, tree) in trees.items():
            functions = self._func_aliases[module]
            modules: dict[str, str] = {}
            package = module.rsplit(".", 1)[0] if "." in module else ""
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module is not None or isinstance(node, ast.ImportFrom) and node.level:
                    base = self._resolve_from(node, package)
                    for alias in node.names:
                        local = alias.asname or alias.name
                        candidate_module = f"{base}.{alias.name}" if base else alias.name
                        if candidate_module in module_names:
                            modules[local] = candidate_module
                        elif f"{base}:{alias.name}" in self.functions:
                            functions.setdefault(local, f"{base}:{alias.name}")
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name in module_names:
                            modules[alias.asname or alias.name] = alias.name
            self._module_aliases[module] = modules

    @staticmethod
    def _resolve_from(node: ast.ImportFrom, package: str) -> str:
        if not node.level:
            return node.module or ""
        parts = package.split(".") if package else []
        if node.level > 1:
            parts = parts[: len(parts) - (node.level - 1)]
        base = ".".join(parts)
        if node.module:
            base = f"{base}.{node.module}" if base else node.module
        return base

    def resolve_call(self, module: str, dotted: str) -> str | None:
        if "." not in dotted:
            return self._func_aliases.get(module, {}).get(dotted)
        head, attr = dotted.rsplit(".", 1)
        target_module = self._module_aliases.get(module, {}).get(head)
        if target_module is None:
            return None
        qualname = f"{target_module}:{attr}"
        return qualname if qualname in self.functions else None


@dataclass(frozen=True)
class _Summary:
    sinks: tuple[tuple[str, int, str, tuple[str, ...]], ...]  # (sink, line, file, path-from-this-function)
    returns_tainted: bool


class InterproceduralAnalyzer:
    def __init__(
        self,
        index: ProjectIndex,
        max_depth: int = DEFAULT_MAX_DEPTH,
        max_nodes: int = DEFAULT_MAX_NODES,
        time_budget_s: float = DEFAULT_TIME_BUDGET_S,
    ):
        self.index = index
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        self.time_budget_s = time_budget_s
        self.stats = InterproceduralStats(functions=len(index.functions))
        self._memo: dict[tuple[str, frozenset[str], int], _Summary] = {}
        self._started = 0.0

    def _budget_exhausted(self) -> bool:
        if self.stats.analyses >= self.max_nodes:
            self.stats.truncated.append("max_nodes")
            return True
        if time.monotonic() - self._started > self.time_budget_s:
            self.stats.truncated.append("time_budget")
            return True
        return False

    def analyze(self) -> list[InterproceduralEdge]:
        self._started = time.monotonic()
        edges: list[InterproceduralEdge] = []
        seen: set[tuple[str, str, int, tuple[str, ...]]] = set()
        for info in self.index.functions.values():
            if not info.is_route:
                continue
            route_params = frozenset(p for p in info.params if p not in info.depends_params and p not in {"self", "request"})
            summary = self._summarize(info, route_params, self.max_depth, frozenset(), request_is_source=True)
            for sink, line, file, path in summary.sinks:
                key = (info.qualname, sink, line, path)
                if key in seen:
                    continue
                seen.add(key)
                edges.append(
                    InterproceduralEdge(
                        source="request", sink=sink, sink_family=sink_family(sink), file=file, line=line,
                        entry=info.qualname, call_path=path,
                    )
                )
        self.stats.elapsed_s = time.monotonic() - self._started
        return edges

    def _summarize(
        self,
        info: FunctionInfo,
        tainted_params: frozenset[str],
        depth: int,
        stack: frozenset[str],
        request_is_source: bool = False,
    ) -> _Summary:
        key = (info.qualname, tainted_params | ({"<request>"} if request_is_source else set()), depth)
        if key in self._memo:
            return self._memo[key]
        if info.qualname in stack:  # recursion
            return _Summary((), False)
        if self._budget_exhausted():
            return _Summary((), False)
        self.stats.analyses += 1
        self.stats.max_depth_reached = max(self.stats.max_depth_reached, self.max_depth - depth)

        tainted = set(tainted_params)
        sinks: list[tuple[str, int, str, tuple[str, ...]]] = []
        returns_tainted = False
        here = (info.qualname,)

        def taint_of(node: ast.expr) -> bool:
            return self._expr_taint(node, tainted, info, depth, stack | {info.qualname}, request_is_source)

        for stmt in _flatten(info.node.body):
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            for call in ast.walk(stmt):
                if not isinstance(call, ast.Call):
                    continue
                dotted = _dotted(call.func)
                if dotted is None:
                    continue
                sink = sink_for_call(dotted)
                args = list(call.args) + [keyword.value for keyword in call.keywords]
                if sink is not None:
                    if any(taint_of(arg) for arg in args):
                        sinks.append((sink, call.lineno, info.file, here))
                    continue
                callee_name = self.index.resolve_call(info.module, dotted)
                if callee_name is None:
                    continue
                callee = self.index.functions[callee_name]
                callee_tainted = frozenset(
                    callee.params[i] for i, arg in enumerate(call.args) if i < len(callee.params) and taint_of(arg)
                ) | frozenset(kw.arg for kw in call.keywords if kw.arg in callee.params and taint_of(kw.value))
                if not callee_tainted:
                    continue
                if depth <= 0:
                    self.stats.truncated.append("max_depth")
                    continue
                summary = self._summarize(callee, callee_tainted, depth - 1, stack | {info.qualname})
                for sink_type, line, file, path in summary.sinks:
                    sinks.append((sink_type, line, file, here + path))

            if isinstance(stmt, ast.Assign):
                value_tainted = taint_of(stmt.value)
                for target in stmt.targets:
                    for name in _target_names(target):
                        if value_tainted:
                            tainted.add(name)
                        else:
                            tainted.discard(name)
            elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None and isinstance(stmt.target, ast.Name):
                if taint_of(stmt.value):
                    tainted.add(stmt.target.id)
            elif isinstance(stmt, ast.Return) and stmt.value is not None and taint_of(stmt.value):
                returns_tainted = True

        deduped = tuple(dict.fromkeys(sinks))
        summary = _Summary(deduped, returns_tainted)
        self._memo[key] = summary
        return summary

    def _expr_taint(
        self,
        node: ast.expr,
        tainted: set[str],
        info: FunctionInfo,
        depth: int,
        stack: frozenset[str],
        request_is_source: bool,
    ) -> bool:
        def recurse(child: ast.expr) -> bool:
            return self._expr_taint(child, tainted, info, depth, stack, request_is_source)

        if request_is_source and is_request_source_expression(node):
            return True
        if isinstance(node, ast.Name):
            return node.id in tainted
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            return recurse(node.value)
        if isinstance(node, ast.Call):
            dotted = _dotted(node.func)
            callee_name = self.index.resolve_call(info.module, dotted) if dotted else None
            if callee_name is not None and depth > 0:
                callee = self.index.functions[callee_name]
                callee_tainted = frozenset(
                    callee.params[i] for i, arg in enumerate(node.args) if i < len(callee.params) and recurse(arg)
                )
                if not callee_tainted:
                    return False
                return self._summarize(callee, callee_tainted, depth - 1, stack).returns_tainted
            if recurse(node.func):
                return True
            return any(recurse(arg) for arg in node.args) or any(recurse(kw.value) for kw in node.keywords)
        if isinstance(node, ast.BinOp):
            return recurse(node.left) or recurse(node.right)
        if isinstance(node, ast.JoinedStr):
            return any(recurse(value.value) for value in node.values if isinstance(value, ast.FormattedValue))
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(recurse(elt) for elt in node.elts)
        if isinstance(node, ast.Dict):
            return any(recurse(value) for value in node.values if value is not None)
        if isinstance(node, ast.IfExp):
            return recurse(node.body) or recurse(node.orelse)
        return False


def _target_names(target: ast.expr) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [name for elt in target.elts for name in _target_names(elt)]
    return []


def _flatten(stmts: list[ast.stmt]) -> list[ast.stmt]:
    flat: list[ast.stmt] = []
    for stmt in stmts:
        flat.append(stmt)
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for attr in ("body", "orelse", "finalbody"):
            block = getattr(stmt, attr, None)
            if isinstance(block, list) and block and isinstance(block[0], ast.stmt):
                flat.extend(_flatten(block))
        for handler in getattr(stmt, "handlers", None) or []:
            flat.extend(_flatten(handler.body))
    return flat


def trace_interprocedural(
    root: Path | str,
    files: list[Path],
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_nodes: int = DEFAULT_MAX_NODES,
    time_budget_s: float = DEFAULT_TIME_BUDGET_S,
) -> tuple[list[InterproceduralEdge], InterproceduralStats]:
    index = ProjectIndex(Path(root), [Path(file) for file in files])
    analyzer = InterproceduralAnalyzer(index, max_depth=max_depth, max_nodes=max_nodes, time_budget_s=time_budget_s)
    edges = analyzer.analyze()
    return edges, analyzer.stats
