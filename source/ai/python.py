from __future__ import annotations

import re
from dataclasses import dataclass, field

# P3.2-4 (roadmap v3.2.0 Source Intelligence): file-level capability
# signals for AI SDK usage, vector retrieval, and tool/function-call
# binding. Prompt *construction* reaching one of these calls with a
# request-derived value is source/dataflow/python.py's job (it already
# reports that as a "prompt_injection_sink" dataflow edge with real
# file/line evidence) -- these hints are the broader, presence-only
# signal: "this file talks to an LLM/vector store/tool-calling API at
# all", regardless of whether a taint path was traced to it.
_LLM_SDK_PATTERNS = [
    re.compile(r"\bimport\s+openai\b"),
    re.compile(r"\bfrom\s+openai\s+import"),
    re.compile(r"\bimport\s+anthropic\b"),
    re.compile(r"\bfrom\s+anthropic\s+import"),
    re.compile(r"google\.generativeai"),
    re.compile(r"ChatCompletion\.create"),
    re.compile(r"client\.messages\.create"),
    re.compile(r"chat\.completions\.create"),
    # P4.2-E (roadmap v4.2.0 Source Intelligence Expansion): JS/TS's
    # require()/ESM import syntax and SDK class instantiation -- this
    # whole function already runs unconditionally on every file
    # regardless of language (source/analyzers.py's _find_llm_integration
    # never gated it), but the patterns above only recognized Python's
    # `import X`/`from X import` form, so a JS/TS file's `require('openai')`
    # or `import OpenAI from 'openai'` went undetected until now.
    re.compile(r"require\(\s*[\"']openai[\"']\s*\)"),
    re.compile(r"from\s+[\"']openai[\"']"),
    re.compile(r"require\(\s*[\"']@anthropic-ai/sdk[\"']\s*\)"),
    re.compile(r"from\s+[\"']@anthropic-ai/sdk[\"']"),
    re.compile(r"require\(\s*[\"']@google/generative-ai[\"']\s*\)"),
    re.compile(r"from\s+[\"']@google/generative-ai[\"']"),
    re.compile(r"\bnew\s+OpenAI\s*\("),
    re.compile(r"\bnew\s+Anthropic\s*\("),
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

_DYNAMIC_VALIDATION_HINTS = {
    "llm": (
        "probe reachable endpoints in this file with prompt_injection/system_prompt_leak testcases "
        "and compare against a canary-based negative control"
    ),
    "rag": (
        "probe with indirect/retrieval-context injection testcases (RAG Test Harness) to check whether "
        "retrieved content can override instructions"
    ),
    "agent": (
        "probe with tool_abuse testcases to check whether tool/function-call bindings can be coerced "
        "into unintended actions"
    ),
}


@dataclass(frozen=True)
class AICapabilityHint:
    kind: str  # "llm" | "rag" | "agent"
    file: str
    signals: list[str] = field(default_factory=list)
    confidence: float = 0.5
    dynamic_validation_hint: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "file": self.file,
            "signals": self.signals,
            "confidence": self.confidence,
            "dynamic_validation_hint": self.dynamic_validation_hint,
        }


def find_ai_capability_hints(path: str, text: str) -> list[AICapabilityHint]:
    hints: list[AICapabilityHint] = []
    llm_signals = [pattern.pattern for pattern in _LLM_SDK_PATTERNS if pattern.search(text)]
    if llm_signals:
        hints.append(AICapabilityHint("llm", path, llm_signals, 0.75, _DYNAMIC_VALIDATION_HINTS["llm"]))
    rag_signals = [pattern.pattern for pattern in _RAG_PATTERNS if pattern.search(text)]
    if rag_signals:
        hints.append(AICapabilityHint("rag", path, rag_signals, 0.5, _DYNAMIC_VALIDATION_HINTS["rag"]))
    agent_signals = [pattern.pattern for pattern in _AGENT_PATTERNS if pattern.search(text)]
    if agent_signals:
        hints.append(AICapabilityHint("agent", path, agent_signals, 0.4, _DYNAMIC_VALIDATION_HINTS["agent"]))
    return hints
