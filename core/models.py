from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:12]}"


class FindingStatus(str, Enum):
    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    UNSTABLE = "unstable"


@dataclass(frozen=True)
class Target:
    kind: str
    base_url: str
    capabilities: dict[str, Any]
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("target"))
    created_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class CapabilityProfile:
    chat: bool = True
    system_prompt_control: bool = False
    sessions: bool = False
    tools: bool = False
    rag: bool = False
    memory: bool = False
    files: bool = False
    multimodal: bool = False

    def supports(self, required: list[str]) -> bool:
        return all(bool(getattr(self, name, False)) for name in required)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Asset:
    run_id: str
    target_id: str
    domain: str
    source: str
    in_scope: bool = False
    id: str = field(default_factory=lambda: new_id("asset"))
    created_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class Endpoint:
    run_id: str
    target_id: str
    url: str
    method: str
    source: str
    status_code: int | None = None
    classification: str = "unclassified"
    in_scope: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("endpoint"))
    created_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class Run:
    target_id: str
    policy_hash: str
    fingerprint: str
    id: str = field(default_factory=lambda: new_id("run"))
    created_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class SessionState:
    run_id: str
    target_id: str
    status: str = "active"
    id: str = field(default_factory=lambda: new_id("session"))
    created_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class ExecutionCheckpoint:
    run_id: str
    trace_id: str
    testcase_id: str
    idempotency_key: str
    status: str
    attempts: int = 0
    error: str | None = None
    id: str = field(default_factory=lambda: new_id("checkpoint"))
    updated_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class StoredTestcase:
    id: str
    name: str
    category: str
    content_hash: str
    frameworks: dict[str, list[str]] = field(default_factory=dict)
    version: str = "local"


@dataclass(frozen=True)
class PromptRecord:
    testcase_id: str
    prompt_hash: str
    text: str
    mutation_id: str | None = None
    id: str = field(default_factory=lambda: new_id("prompt"))


@dataclass(frozen=True)
class MutationRecord:
    testcase_id: str
    strategy: str
    prompt_hash: str
    parent_mutation_id: str | None = None
    generation: int = 0
    id: str = field(default_factory=lambda: new_id("mutation"))


@dataclass(frozen=True)
class TraceEvent:
    trace_id: str
    sequence: int
    event_type: str
    artifact_ref: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=utc_now)
    id: str = field(default_factory=lambda: new_id("event"))


@dataclass(frozen=True)
class Trace:
    run_id: str
    testcase_id: str
    id: str = field(default_factory=lambda: new_id("trace"))
    created_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class RequestRecord:
    run_id: str
    trace_id: str
    testcase_id: str
    prompt_hash: str
    artifact_ref: str | None = None
    latency_ms: int | None = None
    token_count: int | None = None
    cost_usd: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("request"))
    created_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class ResponseRecord:
    request_id: str
    trace_id: str
    status_code: int
    artifact_ref: str | None = None
    latency_ms: int | None = None
    token_count: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("response"))
    created_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class Judgement:
    run_id: str
    testcase_id: str
    judge_type: str
    passed: bool
    score: float
    reason: str
    evidence_ref: str | None = None
    id: str = field(default_factory=lambda: new_id("judgement"))


@dataclass(frozen=True)
class SecretFinding:
    run_id: str
    target_id: str
    detector: str
    source: str
    location: str
    verified: bool
    redacted_secret: str
    raw_artifact_ref: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("secret"))
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Finding:
    run_id: str
    testcase_id: str
    title: str
    category: str
    status: FindingStatus
    confidence: float
    severity: str
    evidence_ref: str
    # P3.1-2 (roadmap v3.1.0): "single" (default, the original per-testcase
    # path) or "scenario" -- a scenario-origin finding's spec is a
    # self-contained snapshot (scenario_id/step_id/steps) so `reproduce
    # <finding-id>` can replay it later without needing the original
    # --scenarios YAML file, the same way single findings replay the exact
    # stored prompt rather than whatever the current suite file contains.
    reproduction_spec: dict[str, Any] = field(default_factory=lambda: {"type": "single"})
    id: str = field(default_factory=lambda: new_id("finding"))


@dataclass(frozen=True)
class Evidence:
    run_id: str
    kind: str
    path: str
    sha256: str
    sanitized: bool
    id: str = field(default_factory=lambda: new_id("evidence"))


@dataclass(frozen=True)
class Reproduction:
    finding_id: str
    attempts: int
    successes: int
    control_passed: bool
    status: FindingStatus
    id: str = field(default_factory=lambda: new_id("repro"))

    @property
    def success_rate(self) -> float:
        if self.attempts == 0:
            return 0.0
        return self.successes / self.attempts


@dataclass(frozen=True)
class ReportRecord:
    run_id: str
    path: str
    kind: str = "shareable"
    id: str = field(default_factory=lambda: new_id("report"))
