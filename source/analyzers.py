from __future__ import annotations

import os
import re
from pathlib import Path

from attack_surface.models import AttackSurfaceItem
from source.ai.python import find_ai_capability_hints
from source.auth.javascript import find_auth_guards as find_auth_guards_js
from source.auth.python import find_auth_guards
from source.contract import LanguageSourceAnalyzer, get_language_analyzer, register_language_analyzer
from source.dataflow.javascript import trace_dataflow as trace_dataflow_js
from source.dataflow.python import trace_dataflow
from source.ingestion import SourceFile
from source.interprocedural.python import trace_interprocedural
from source.sinks.python import sink_family

# P4.2-A: python's dataflow/auth backends, registered through the same
# contract a future language's backend (P4.2-D) plugs into -- behavior
# for python files is unchanged, just reached via a lookup now.
register_language_analyzer(
    LanguageSourceAnalyzer(language="python", trace_dataflow=trace_dataflow, find_auth_guards=find_auth_guards)
)
# P4.2-D: JS/TS backends -- registered under both language keys since
# source/ingestion.py's language detection reports "javascript" for
# .js/.jsx and "typescript" for .ts/.tsx (source/routes.py's own
# _AST_PARSERS dict makes the same both-keys-one-implementation choice
# for route extraction).
for _js_language in ("javascript", "typescript"):
    register_language_analyzer(
        LanguageSourceAnalyzer(
            language=_js_language, trace_dataflow=trace_dataflow_js, find_auth_guards=find_auth_guards_js
        )
    )

_INPUT_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "python": [
        re.compile(r"request\.(args|form|json|files|cookies|headers)\b"),
        re.compile(r"request\.get_json\("),
    ],
    "javascript": [re.compile(r"req\.(query|body|params|cookies|headers)\b")],
    "typescript": [re.compile(r"req\.(query|body|params|cookies|headers)\b")],
}

_SINK_PATTERNS = [
    ("code_execution", re.compile(r"\b(?:eval|exec)\s*\(")),
    ("os_command", re.compile(r"\bos\.system\(|subprocess\.(?:run|call|Popen|check_output)\(")),
    ("deserialization", re.compile(r"\bpickle\.loads?\(|yaml\.load\(")),
    ("template_injection", re.compile(r"\brender_template_string\(")),
    ("sql_string_build", re.compile(r'(?:execute|query)\(\s*(?:f["\']|["\'][^"\']*["\']\s*(?:%|\+)|\.format\()')),
]

# Only the detector name/location is ever stored -- never the matched value
# itself, matching the project's evidence-security principle established
# for the TruffleHog adapter (tools/adapters/secrets/trufflehog.py).
_SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("generic_api_key", re.compile(r'(?i)(?:api[_-]?key|secret|token)\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']')),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]

def analyze_files(
    files: list[SourceFile],
    routes: list[AttackSurfaceItem] | None = None,
    stats_out: dict[str, object] | None = None,
) -> list[AttackSurfaceItem]:
    """`routes` (extract_routes' own output) is optional but, when given,
    lets P3.2-4's auth-guard check know which functions are actually
    route handlers -- see _find_auth_guards. `stats_out`, if given,
    receives the P4.6 interprocedural pass's stats (caps hit etc.).
    """
    route_handlers_by_file: dict[str, set[str]] = {}
    for route_item in routes or []:
        handler = route_item.metadata.get("handler")
        file = route_item.metadata.get("file")
        if handler and file:
            route_handlers_by_file.setdefault(str(file), set()).add(str(handler))

    items: list[AttackSurfaceItem] = []
    for source_file in files:
        try:
            text = source_file.path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        # P4.7 WP-08: one pathological file (deep nesting, huge literal)
        # must never abort the whole audit -- its partial results are
        # dropped and the failure is recorded instead.
        try:
            file_items: list[AttackSurfaceItem] = []
            file_items.extend(_find_inputs(source_file, text))
            file_items.extend(_find_sinks(source_file, text))
            file_items.extend(_find_secrets(source_file, text))
            file_items.extend(_find_llm_integration(source_file, text))
            file_items.extend(_find_dataflow_edges(source_file, text))
            file_items.extend(_find_auth_guards(source_file, text, route_handlers_by_file.get(str(source_file.path), set())))
        except (RecursionError, MemoryError) as exc:
            if stats_out is not None:
                stats_out.setdefault("file_errors", []).append({"file": str(source_file.path), "error": type(exc).__name__})
            continue
        items.extend(file_items)
    try:
        items.extend(_find_interprocedural_edges(files, routes or [], items, stats_out))
    except (RecursionError, MemoryError) as exc:
        if stats_out is not None:
            stats_out.setdefault("truncated", []).append(f"interprocedural_{type(exc).__name__}")
    return items


def _find_interprocedural_edges(
    files: list[SourceFile],
    routes: list[AttackSurfaceItem],
    items: list[AttackSurfaceItem],
    stats_out: dict[str, object] | None,
) -> list[AttackSurfaceItem]:
    """P4.6 WP-04: route -> helper/service -> sink chains across Python
    files (source/interprocedural/python.py). Only edges the per-file
    tracer didn't already report are added, each carrying its call
    path, the route it starts at, and that route's auth-guard hint."""
    python_files = [source_file.path for source_file in files if source_file.language == "python"]
    if not python_files:
        return []
    root = Path(os.path.commonpath([str(path.resolve().parent) for path in python_files]))
    # Import root = the directory *containing* the top-level package, so
    # `from app.services import x` resolves when every file lives under app/.
    while (root / "__init__.py").exists() and root.parent != root:
        root = root.parent
    edges, stats = trace_interprocedural(root, python_files)
    if stats_out is not None:
        stats_out.update(stats.to_dict())

    already = {
        (str(Path(str(item.metadata.get("file"))).resolve()), item.metadata.get("line"), item.metadata.get("sink_type"))
        for item in items
        if item.asset_type == "dataflow"
    }
    route_by_handler = {
        (str(Path(str(route.metadata.get("file"))).resolve()), route.metadata.get("handler")): route
        for route in routes
        if route.metadata.get("handler")
    }
    auth_by_handler = {
        (str(Path(str(item.metadata.get("file"))).resolve()), item.metadata.get("handler")): item
        for item in items
        if item.asset_type == "auth" and item.metadata.get("handler")
    }

    found: list[AttackSurfaceItem] = []
    for edge in edges:
        key = (str(Path(edge.file).resolve()), edge.line, edge.sink)
        if key in already:
            continue
        already.add(key)
        entry_function = edge.entry.split(":", 1)[1]
        entry_file = next(
            (str(path.resolve()) for path in python_files if _module_matches(root, path, edge.entry.split(":", 1)[0])), None
        )
        route = route_by_handler.get((entry_file, entry_function)) if entry_file else None
        auth = auth_by_handler.get((entry_file, entry_function)) if entry_file else None
        metadata: dict[str, object] = {
            "sink_type": edge.sink,
            "sink_family": edge.sink_family,
            "source": edge.source,
            "file": edge.file,
            "line": edge.line,
            "entry": edge.entry,
            "call_path": list(edge.call_path),
            "hops": edge.hops,
            "analysis": "interprocedural",
        }
        if route is not None:
            metadata["route"] = f"{route.metadata.get('method')} {route.location}"
        if auth is not None:
            metadata["auth_guard_detected"] = bool(auth.metadata.get("detected"))
            metadata["auth_guards"] = list(auth.metadata.get("guard_names", []))
        found.append(
            AttackSurfaceItem(
                source_type="source",
                asset_type="dataflow",
                location=f"{edge.file}:{edge.line}",
                metadata=metadata,
                # Each extra hop is one more resolution step that could be
                # wrong, so confidence decays slightly with chain length.
                confidence=round(max(0.6, 0.85 - 0.05 * edge.hops), 2),
                evidence_refs=[f"{edge.file}:{edge.line}", *[f"call:{step}" for step in edge.call_path]],
            )
        )
    return found


def _module_matches(root: Path, path: Path, module: str) -> bool:
    try:
        relative = path.resolve().relative_to(root.resolve()).with_suffix("")
    except ValueError:
        return False
    parts = list(relative.parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) == module


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _find_inputs(source_file: SourceFile, text: str) -> list[AttackSurfaceItem]:
    items: list[AttackSurfaceItem] = []
    seen: set[tuple[str, int]] = set()
    for pattern in _INPUT_PATTERNS.get(source_file.language, []):
        for match in pattern.finditer(text):
            line = _line_of(text, match.start())
            key = (match.group(0), line)
            if key in seen:
                continue
            seen.add(key)
            items.append(
                AttackSurfaceItem(
                    source_type="source",
                    asset_type="parameter",
                    location=f"{source_file.path}:{line}",
                    metadata={"name": match.group(0), "position": "request", "file": str(source_file.path), "line": line},
                    confidence=0.5,
                    evidence_refs=[f"{source_file.path}:{line}"],
                )
            )
    return items


def _find_sinks(source_file: SourceFile, text: str) -> list[AttackSurfaceItem]:
    items: list[AttackSurfaceItem] = []
    for sink_type, pattern in _SINK_PATTERNS:
        for match in pattern.finditer(text):
            line = _line_of(text, match.start())
            items.append(
                AttackSurfaceItem(
                    source_type="source",
                    asset_type="function",
                    location=f"{source_file.path}:{line}",
                    metadata={"sink_type": sink_type, "file": str(source_file.path), "line": line},
                    confidence=0.55,
                    evidence_refs=[f"{source_file.path}:{line}"],
                )
            )
    return items


def _find_secrets(source_file: SourceFile, text: str) -> list[AttackSurfaceItem]:
    items: list[AttackSurfaceItem] = []
    for secret_type, pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            line = _line_of(text, match.start())
            items.append(
                AttackSurfaceItem(
                    source_type="source",
                    asset_type="secret",
                    location=f"{source_file.path}:{line}",
                    metadata={"secret_type": secret_type, "file": str(source_file.path), "line": line},
                    confidence=0.7,
                    evidence_refs=[f"{source_file.path}:{line}"],
                )
            )
    return items


def _find_dataflow_edges(source_file: SourceFile, text: str) -> list[AttackSurfaceItem]:
    """P3.2-3 (roadmap v3.2.0 Source Intelligence), extended by P4.2-D
    to also cover javascript/typescript via source/dataflow/javascript.py,
    both reached through the P4.2-A language-analyzer registry rather
    than a hardcoded language check. A distinct, higher-confidence
    signal from _find_sinks' plain "this dangerous call exists somewhere
    in the file" regex match -- this only fires when a request-derived
    value is actually traced reaching that call, with real source->sink
    evidence rather than a string-shape guess.
    """
    analyzer = get_language_analyzer(source_file.language)
    if analyzer is None or analyzer.trace_dataflow is None:
        return []
    items: list[AttackSurfaceItem] = []
    for edge in analyzer.trace_dataflow(source_file.path, text):
        items.append(
            AttackSurfaceItem(
                source_type="source",
                asset_type="dataflow",
                location=f"{source_file.path}:{edge.line}",
                metadata={
                    "sink_type": edge.sink,
                    "sink_family": sink_family(edge.sink),
                    "source": edge.source,
                    "file": edge.file,
                    "line": edge.line,
                },
                confidence=0.85,
                evidence_refs=[f"{source_file.path}:{edge.line}"],
            )
        )
    return items


def _find_llm_integration(source_file: SourceFile, text: str) -> list[AttackSurfaceItem]:
    items: list[AttackSurfaceItem] = []
    for hint in find_ai_capability_hints(str(source_file.path), text):
        metadata: dict[str, object] = {
            "file": hint.file,
            "signals": hint.signals,
            "dynamic_validation_hint": hint.dynamic_validation_hint,
        }
        if hint.kind == "llm":
            metadata["llm_detected"] = True
        items.append(
            AttackSurfaceItem(
                source_type="source",
                asset_type=hint.kind,
                location=hint.file,
                metadata=metadata,
                confidence=hint.confidence,
                evidence_refs=[hint.file],
            )
        )
    return items


def _find_auth_guards(source_file: SourceFile, text: str, route_handlers: set[str]) -> list[AttackSurfaceItem]:
    """P3.2-4 (roadmap v3.2.0 Source Intelligence), extended by P4.2-D
    to also cover javascript/typescript via source/auth/javascript.py.
    A route-level auth posture *candidate*, never a confirmed absence --
    see source/auth/python.py's AuthGuardHint docstring for why.
    """
    analyzer = get_language_analyzer(source_file.language)
    if analyzer is None or analyzer.find_auth_guards is None:
        return []
    items: list[AttackSurfaceItem] = []
    for hint in analyzer.find_auth_guards(source_file.path, text, route_handlers):
        items.append(
            AttackSurfaceItem(
                source_type="source",
                asset_type="auth",
                location=f"{hint.file}:{hint.line}",
                metadata={
                    **hint.to_dict(),
                    "dynamic_validation_hint": (
                        "before treating guard_detected=False as unauthenticated, send an unauthenticated "
                        "request to this route and confirm it isn't rejected by middleware or a framework "
                        "default this static check can't see"
                    ),
                },
                confidence=hint.confidence,
                evidence_refs=[f"{hint.file}:{hint.line}"],
            )
        )
    return items
