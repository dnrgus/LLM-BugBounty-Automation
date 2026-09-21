from __future__ import annotations

from core.models import TraceEvent
from scope.policy import PolicyEngine, PolicyDecision


class ApprovalGate:
    def __init__(self, policy: PolicyEngine):
        self.policy = policy

    def evaluate(self, trace_id: str, sequence: int, action: str) -> tuple[PolicyDecision, TraceEvent]:
        decision = self.policy.decide_action(action)
        event = TraceEvent(
            trace_id=trace_id,
            sequence=sequence,
            event_type="approval",
            metadata={"action": action, "decision": decision.to_dict()},
        )
        return decision, event

