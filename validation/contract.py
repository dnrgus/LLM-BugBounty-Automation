from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from core.models import new_id, utc_now


class ValidationStatus(str, Enum):
    """P4.1-A (roadmap v4.1.0 Dynamic Validation Expansion): the unified
    lifecycle every ValidationTask moves through, replacing the split
    that used to exist between validation/planner.py's 3-way
    classification (executable/review_only/unsupported, the *planning*
    outcome) and core.models.FindingStatus (confirmed/rejected/unstable,
    the *execution* outcome) with one state machine covering both.
    """

    PLANNED = "planned"
    BLOCKED = "blocked"
    EXECUTABLE = "executable"
    RUNNING = "running"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    UNSTABLE = "unstable"
    REVIEW_ONLY = "review_only"


# PLANNED is the only valid starting state. CONFIRMED/REJECTED/UNSTABLE/
# REVIEW_ONLY/BLOCKED are all terminal -- a finished task is re-planned
# as a new ValidationTask, never mutated back to an earlier state.
_ALLOWED_TRANSITIONS: dict[ValidationStatus, frozenset[ValidationStatus]] = {
    ValidationStatus.PLANNED: frozenset(
        {ValidationStatus.BLOCKED, ValidationStatus.EXECUTABLE, ValidationStatus.REVIEW_ONLY}
    ),
    ValidationStatus.EXECUTABLE: frozenset({ValidationStatus.RUNNING, ValidationStatus.BLOCKED}),
    ValidationStatus.RUNNING: frozenset(
        {ValidationStatus.CONFIRMED, ValidationStatus.REJECTED, ValidationStatus.UNSTABLE, ValidationStatus.REVIEW_ONLY}
    ),
    ValidationStatus.BLOCKED: frozenset(),
    ValidationStatus.CONFIRMED: frozenset(),
    ValidationStatus.REJECTED: frozenset(),
    ValidationStatus.UNSTABLE: frozenset(),
    ValidationStatus.REVIEW_ONLY: frozenset(),
}


class InvalidValidationStateTransition(ValueError):
    pass


def assert_valid_transition(current: ValidationStatus, target: ValidationStatus) -> None:
    if target not in _ALLOWED_TRANSITIONS.get(current, frozenset()):
        raise InvalidValidationStateTransition(f"cannot transition from {current.value} to {target.value}")


@dataclass
class ValidationTask:
    candidate_id: str
    validator_type: str
    prerequisites: list[str] = field(default_factory=list)
    risk_level: str = "low"
    required_sessions: int = 0
    budget_hint: dict[str, object] = field(default_factory=dict)
    status: ValidationStatus = ValidationStatus.PLANNED
    id: str = field(default_factory=lambda: new_id("vtask"))
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)

    def transition(self, target: ValidationStatus) -> None:
        assert_valid_transition(self.status, target)
        self.status = target
        self.updated_at = utc_now()

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "candidate_id": self.candidate_id,
            "validator_type": self.validator_type,
            "prerequisites": list(self.prerequisites),
            "risk_level": self.risk_level,
            "required_sessions": self.required_sessions,
            "budget_hint": dict(self.budget_hint),
            "status": self.status.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> ValidationTask:
        return cls(
            id=data["id"],
            candidate_id=data["candidate_id"],
            validator_type=data["validator_type"],
            prerequisites=list(data.get("prerequisites", [])),
            risk_level=data.get("risk_level", "low"),
            required_sessions=int(data.get("required_sessions", 0)),
            budget_hint=dict(data.get("budget_hint", {})),
            status=ValidationStatus(data["status"]),
            created_at=data.get("created_at", utc_now()),
            updated_at=data.get("updated_at", utc_now()),
        )


@dataclass(frozen=True)
class ValidationEvidenceRef:
    evidence_id: str
    kind: str
    description: str = ""

    def to_dict(self) -> dict[str, object]:
        return {"evidence_id": self.evidence_id, "kind": self.kind, "description": self.description}


@dataclass(frozen=True)
class ValidationResult:
    task_id: str
    status: ValidationStatus
    confidence: float
    evidence_refs: list[str] = field(default_factory=list)
    observations: list[dict[str, object]] = field(default_factory=list)
    id: str = field(default_factory=lambda: new_id("vresult"))
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "task_id": self.task_id,
            "status": self.status.value,
            "confidence": self.confidence,
            "evidence_refs": list(self.evidence_refs),
            "observations": list(self.observations),
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> ValidationResult:
        return cls(
            id=data.get("id") or new_id("vresult"),
            task_id=data["task_id"],
            status=ValidationStatus(data["status"]),
            confidence=float(data["confidence"]),
            evidence_refs=list(data.get("evidence_refs", [])),
            observations=list(data.get("observations", [])),
            created_at=data.get("created_at", utc_now()),
        )


@dataclass(frozen=True)
class ValidationStrategy:
    """Describes one validator_type's capabilities/defaults -- a small
    registry entry (analogous to packs/registry.py's AttackPack) a
    planner can use to build a ValidationTask with sane defaults before
    a validator-specific plan customizes it further."""

    validator_type: str
    description: str
    default_risk_level: str = "low"
    supports_asset_types: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "validator_type": self.validator_type,
            "description": self.description,
            "default_risk_level": self.default_risk_level,
            "supports_asset_types": list(self.supports_asset_types),
        }


DEFAULT_STRATEGIES: tuple[ValidationStrategy, ...] = (
    ValidationStrategy("llm_core", "existing testcase_suite pack: prompt_injection/system_prompt_leak", "low", ("llm",)),
    ValidationStrategy("rag_injection", "existing testcase_suite pack: indirect_injection", "low", ("rag",)),
    ValidationStrategy("agent_tool_abuse", "existing testcase_suite pack: tool_abuse", "medium", ("agent",)),
    ValidationStrategy("endpoint", "generic endpoint reachability/behavior probe", "low", ("endpoint",)),
    ValidationStrategy("auth", "auth-context comparison probe", "medium", ("auth",)),
    ValidationStrategy("dataflow", "runtime correlation of a traced static dataflow edge", "high", ("dataflow",)),
)
