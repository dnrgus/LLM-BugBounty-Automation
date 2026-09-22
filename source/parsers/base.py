from __future__ import annotations

from pathlib import Path
from typing import Protocol

from source.models import ParserResult


class SourceParser(Protocol):
    """P3.2-1 (roadmap v3.2.0 Source Intelligence): the common interface
    every per-language AST parser implements, so SOURCE MODE can add a
    new language's parser without any caller needing to know about that
    language specifically -- everything downstream only ever sees a
    ParserResult.
    """

    language: str

    def parse_file(self, path: Path, text: str) -> ParserResult: ...


def merge_results(results: list[ParserResult]) -> ParserResult:
    """Combines many single-file ParserResults for one language into one."""
    if not results:
        return ParserResult(language="unknown")
    language = results[0].language
    return ParserResult(
        language=language,
        routes=[route for result in results for route in result.routes],
        calls=[call for result in results for call in result.calls],
        edges=[edge for result in results for edge in result.edges],
        errors=[error for result in results for error in result.errors],
    )
