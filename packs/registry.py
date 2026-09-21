from __future__ import annotations

from dataclasses import dataclass, field

from live.classify import TargetKind


@dataclass(frozen=True)
class AttackPack:
    """A named, selectable bundle of testing capability (design doc
    section 8: Pack Selector).

    U6 defines the pack model and selection logic against a target's
    classified capabilities, policy, and budget. U7 wires each pack's
    tool_ids to real adapters/verifiers (Nuclei/Dalfox/TruffleHog, the
    existing testcase suite) -- this registry is the seam between them.
    """

    id: str
    name: str
    applies_to: tuple[TargetKind, ...]
    testing_categories: tuple[str, ...]
    estimated_request_cost: int
    tool_ids: tuple[str, ...] = field(default_factory=tuple)
    description: str = ""


DEFAULT_PACKS: tuple[AttackPack, ...] = (
    AttackPack(
        id="llm_core",
        name="LLM Core Attack Suite",
        applies_to=("llm",),
        testing_categories=("prompt_injection", "system_prompt_leak"),
        estimated_request_cost=20,
        tool_ids=("testcase_suite",),
        description="Existing testcase-driven prompt injection / system-prompt-leak suite.",
    ),
    AttackPack(
        id="rag_injection",
        name="RAG Indirect Injection Suite",
        applies_to=("rag",),
        testing_categories=("indirect_injection", "rag_security"),
        estimated_request_cost=15,
        tool_ids=("testcase_suite",),
        description="Existing indirect/RAG-context injection testcases.",
    ),
    AttackPack(
        id="agent_tool_abuse",
        name="Agent Tool-Call Abuse Suite",
        applies_to=("agent",),
        testing_categories=("tool_abuse",),
        estimated_request_cost=15,
        tool_ids=("testcase_suite",),
        description="Existing agent/tool-call abuse testcases.",
    ),
    AttackPack(
        id="web_scan",
        name="Web Vulnerability Scan",
        applies_to=("web", "api", "graphql"),
        testing_categories=("automated_scanning",),
        estimated_request_cost=50,
        tool_ids=("nuclei",),
        description="External web vulnerability scanning (Nuclei).",
    ),
    AttackPack(
        id="api_fuzz",
        name="API Parameter Fuzzing",
        applies_to=("api", "graphql"),
        testing_categories=("automated_scanning",),
        estimated_request_cost=50,
        tool_ids=("dalfox",),
        description="Reflected-parameter / XSS-style fuzzing (Dalfox).",
    ),
    AttackPack(
        id="secret_scan",
        name="Secret Exposure Scan",
        applies_to=("web", "api", "graphql", "llm", "rag", "agent", "websocket"),
        testing_categories=("automated_scanning",),
        estimated_request_cost=10,
        tool_ids=("trufflehog",),
        description="Secret/credential exposure scanning (TruffleHog) over reachable pages/JS.",
    ),
)
