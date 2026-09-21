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
class Run:
    target_id: str
    policy_hash: str
    fingerprint: str
    id: str = field(default_factory=lambda: new_id("run"))
    created_at: str = field(default_factory=utc_now)


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
class Finding:
    run_id: str
    testcase_id: str
    title: str
    category: str
    status: FindingStatus
    confidence: float
    severity: str
    evidence_ref: str
    id: str = field(default_factory=lambda: new_id("finding"))


@dataclass(frozen=True)
class Evidence:
    run_id: str
    kind: str
    path: str
    sha256: str
    sanitized: bool
    id: str = field(default_factory=lambda: new_id("evidence"))

