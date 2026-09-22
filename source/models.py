from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class RouteNode:
    """One HTTP route extracted by a language parser (P3.2-1: roadmap
    v3.2.0 Source Intelligence)."""

    method: str
    path: str
    handler: str
    file: str
    line: int
    framework: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class CallNode:
    """One function-call site, keyed by its dotted callee name as written
    (e.g. "os.system", "eval") -- raw material for later phases (P3.2-3
    dataflow, sink detection), not itself a sink classification."""

    name: str
    file: str
    line: int
    enclosing_function: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class DataEdge:
    """A traced source -> sink relationship. Declared now so
    ParserResult's shape is stable across phases; not yet populated by
    the P3.2-1 Python AST parser itself (P3.2-3 wires this up)."""

    source: str
    sink: str
    file: str
    line: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ParserResult:
    """One language parser's output for a single file (or, via
    source.parsers.base.merge_results, many files)."""

    language: str
    routes: list[RouteNode] = field(default_factory=list)
    calls: list[CallNode] = field(default_factory=list)
    edges: list[DataEdge] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "language": self.language,
            "routes": [route.to_dict() for route in self.routes],
            "calls": [call.to_dict() for call in self.calls],
            "edges": [edge.to_dict() for edge in self.edges],
            "errors": self.errors,
        }
