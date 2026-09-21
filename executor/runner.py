from __future__ import annotations

from core.models import Run, Trace, TraceEvent
from executor.approval import ApprovalGate
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from targets.base import TargetAdapter, TargetResponse
from testcase.schema import Testcase


class Executor:
    def __init__(self, policy: PolicyEngine, target: TargetAdapter, store: SQLiteStore):
        self.policy = policy
        self.target = target
        self.store = store
        self.approval = ApprovalGate(policy)
        self.request_count = 0

    async def execute(self, run: Run, trace: Trace, testcase: Testcase, url: str) -> TargetResponse:
        url_decision = self.policy.validate_url(url)
        self.store.insert_event(
            TraceEvent(
                trace_id=trace.id,
                sequence=1,
                event_type="scope_check",
                metadata=url_decision.to_dict(),
            )
        )
        if not url_decision.allowed:
            raise PermissionError(url_decision.reason)

        category_decision = self.policy.validate_testcase(testcase.category)
        self.store.insert_event(
            TraceEvent(
                trace_id=trace.id,
                sequence=2,
                event_type="policy_check",
                metadata=category_decision.to_dict(),
            )
        )
        if not category_decision.allowed:
            raise PermissionError(category_decision.reason)

        if self.policy.max_requests_per_run and self.request_count >= self.policy.max_requests_per_run:
            raise RuntimeError("request budget exhausted")

        decision, event = self.approval.evaluate(trace.id, 3, "network_get")
        self.store.insert_event(event)
        if not decision.allowed:
            raise PermissionError(decision.reason)

        self.store.insert_event(
            TraceEvent(
                trace_id=trace.id,
                sequence=4,
                event_type="llm_call",
                metadata={"testcase_id": testcase.id},
            )
        )
        self.request_count += 1
        response = await self.target.send(testcase.prompt, session=trace.id)
        self.store.insert_event(
            TraceEvent(
                trace_id=trace.id,
                sequence=5,
                event_type="final_response",
                metadata={"length": len(response.text)},
            )
        )
        return response

