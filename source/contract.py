from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from source.auth.python import AuthGuardHint
from source.models import DataEdge

TraceDataflowFn = Callable[[Path, str], list[DataEdge]]
FindAuthGuardsFn = Callable[[Path, str, "set[str]"], list[AuthGuardHint]]


@dataclass(frozen=True)
class LanguageSourceAnalyzer:
    """P4.2-A (roadmap v4.2.0 Source Intelligence Expansion): one
    language's set of source-intelligence backends, registered once so
    source/analyzers.py dispatches by `source_file.language` instead of
    hardcoding "if python do X, else no-op" per signal type (which is
    what v3.2.0 through v4.1.0 actually did -- trace_dataflow was gated
    `if source_file.language != "python": return []`, and
    find_auth_guards silently no-op'd on non-Python text because
    ast.parse() raises on it).

    A language with no registered analyzer, or one that only
    implements part of the contract (`trace_dataflow` or
    `find_auth_guards` left `None`), contributes no signal for the
    missing piece -- exactly the same "no signal" outcome as before
    this registry existed, just reached through a lookup instead of a
    hardcoded branch.
    """

    language: str
    trace_dataflow: TraceDataflowFn | None = None
    find_auth_guards: FindAuthGuardsFn | None = None


_REGISTRY: dict[str, LanguageSourceAnalyzer] = {}


def register_language_analyzer(analyzer: LanguageSourceAnalyzer) -> None:
    _REGISTRY[analyzer.language] = analyzer


def get_language_analyzer(language: str) -> LanguageSourceAnalyzer | None:
    return _REGISTRY.get(language)


def registered_languages() -> list[str]:
    return sorted(_REGISTRY)
