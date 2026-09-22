from __future__ import annotations

import re

from attack_surface.models import AttackSurfaceItem
from source.dataflow.python import trace_dataflow
from source.ingestion import SourceFile

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
# for the TruffleHog adapter (adapters/secrets/trufflehog.py).
_SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("generic_api_key", re.compile(r'(?i)(?:api[_-]?key|secret|token)\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']')),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]

_LLM_SDK_PATTERNS = [
    re.compile(r"\bimport\s+openai\b"),
    re.compile(r"\bfrom\s+openai\s+import"),
    re.compile(r"\bimport\s+anthropic\b"),
    re.compile(r"\bfrom\s+anthropic\s+import"),
    re.compile(r"google\.generativeai"),
    re.compile(r"ChatCompletion\.create"),
    re.compile(r"client\.messages\.create"),
    re.compile(r"chat\.completions\.create"),
]

_RAG_PATTERNS = [
    re.compile(r"(?i)vectorstore|vector_store"),
    re.compile(r"(?i)embeddings?\."),
    re.compile(r"(?i)retriever|retrieval_chain"),
    re.compile(r"(?i)langchain"),
]

_AGENT_PATTERNS = [
    re.compile(r"(?i)function_call|tool_calls?"),
    re.compile(r"@tool\b"),
    re.compile(r"(?i)\bmcp\b"),
]


def analyze_files(files: list[SourceFile]) -> list[AttackSurfaceItem]:
    items: list[AttackSurfaceItem] = []
    for source_file in files:
        try:
            text = source_file.path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        items.extend(_find_inputs(source_file, text))
        items.extend(_find_sinks(source_file, text))
        items.extend(_find_secrets(source_file, text))
        items.extend(_find_llm_integration(source_file, text))
        items.extend(_find_dataflow_edges(source_file, text))
    return items


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
    """P3.2-3 (roadmap v3.2.0 Source Intelligence): Python-only for now
    (source/dataflow/python.py). A distinct, higher-confidence signal
    from _find_sinks' plain "this dangerous call exists somewhere in the
    file" regex match -- this only fires when a request-derived value is
    actually traced reaching that call, with real source->sink evidence
    rather than a string-shape guess.
    """
    if source_file.language != "python":
        return []
    items: list[AttackSurfaceItem] = []
    for edge in trace_dataflow(source_file.path, text):
        items.append(
            AttackSurfaceItem(
                source_type="source",
                asset_type="dataflow",
                location=f"{source_file.path}:{edge.line}",
                metadata={
                    "sink_type": edge.sink,
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
    if any(pattern.search(text) for pattern in _LLM_SDK_PATTERNS):
        items.append(
            AttackSurfaceItem(
                source_type="source",
                asset_type="llm",
                location=str(source_file.path),
                metadata={"file": str(source_file.path), "llm_detected": True},
                confidence=0.75,
                evidence_refs=[str(source_file.path)],
            )
        )
    if any(pattern.search(text) for pattern in _RAG_PATTERNS):
        items.append(
            AttackSurfaceItem(
                source_type="source",
                asset_type="rag",
                location=str(source_file.path),
                metadata={"file": str(source_file.path)},
                confidence=0.5,
                evidence_refs=[str(source_file.path)],
            )
        )
    if any(pattern.search(text) for pattern in _AGENT_PATTERNS):
        items.append(
            AttackSurfaceItem(
                source_type="source",
                asset_type="agent",
                location=str(source_file.path),
                metadata={"file": str(source_file.path)},
                confidence=0.4,
                evidence_refs=[str(source_file.path)],
            )
        )
    return items
