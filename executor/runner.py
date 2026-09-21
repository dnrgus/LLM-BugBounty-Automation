from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass

from core.models import ExecutionCheckpoint, Run, Trace, TraceEvent
from executor.approval import ApprovalGate
from executor.session import SessionManager
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from targets.base import TargetAdapter, TargetResponse
from testcase.schema import Testcase


@dataclass(frozen=True)
class ExecutorOptions:
    timeout_seconds: float = 10.0
    max_attempts: int = 1
    retry_backoff_seconds: float = 0.0


class Executor:
    def __init__(
        self,
        policy: PolicyEngine,
        target: TargetAdapter,
        store: SQLiteStore,
        options: ExecutorOptions | None = None,
        target_id: str = "target",
    ):
        self.policy = policy
        self.target = target
        self.store = store
        self.approval = ApprovalGate(policy)
        self.options = options or ExecutorOptions()
        self.sessions = SessionManager(target_id=target_id)

    async def execute(
        self,
        run: Run,
        trace: Trace,
        testcase: Testcase,
        url: str,
        idempotency_key: str | None = None,
        session_id: str | None = None,
    ) -> TargetResponse:
        idempotency_key = idempotency_key or self._idempotency_key(run, trace, testcase)
        previous = self.store.get_checkpoint(idempotency_key)
        if previous is not None and previous["status"] == "completed":
            self.store.insert_event(
                TraceEvent(
                    trace_id=trace.id,
                    sequence=1,
                    event_type="checkpoint_resume",
                    metadata={"idempotency_key": idempotency_key, "status": "completed"},
                )
            )
            return TargetResponse(
                prompt=testcase.prompt,
                text="Skipped completed idempotent execution.",
                metadata={"idempotency_key": idempotency_key, "resumed": True},
            )

        session = self.sessions.create(run)
        self.store.insert_session(session)
        self.store.upsert_checkpoint(
            ExecutionCheckpoint(
                run_id=run.id,
                trace_id=trace.id,
                testcase_id=testcase.id,
                idempotency_key=idempotency_key,
                status="started",
            )
        )

        url_decision = self.policy.validate_url(url)
        self.store.insert_event(
            TraceEvent(
                trace_id=trace.id,
                sequence=2,
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
                sequence=3,
                event_type="policy_check",
                metadata=category_decision.to_dict(),
            )
        )
        if not category_decision.allowed:
            raise PermissionError(category_decision.reason)

        budget_decision = self.policy.consume_request_budget()
        self.store.insert_event(
            TraceEvent(
                trace_id=trace.id,
                sequence=4,
                event_type="budget_check",
                metadata=budget_decision.to_dict(),
            )
        )
        if not budget_decision.allowed:
            raise RuntimeError(budget_decision.reason)

        decision, event = self.approval.evaluate(trace.id, 5, "network_get")
        self.store.insert_event(event)
        if not decision.allowed:
            raise PermissionError(decision.reason)

        self.store.insert_event(
            TraceEvent(
                trace_id=trace.id,
                sequence=6,
                event_type="llm_call",
                metadata={"testcase_id": testcase.id, "idempotency_key": idempotency_key},
            )
        )
        response = await self._send_with_retries(run, trace, testcase, idempotency_key, session_id)
        for offset, target_event in enumerate(response.trace_events, start=7):
            self.store.insert_event(
                TraceEvent(
                    trace_id=trace.id,
                    sequence=offset,
                    event_type=f"target_{target_event.event_type}",
                    artifact_ref=target_event.artifact_ref,
                    metadata=target_event.metadata,
                )
            )
        self.store.insert_event(
            TraceEvent(
                trace_id=trace.id,
                sequence=7 + len(response.trace_events),
                event_type="final_response",
                metadata={"length": len(response.text)},
            )
        )
        self.store.upsert_checkpoint(
            ExecutionCheckpoint(
                run_id=run.id,
                trace_id=trace.id,
                testcase_id=testcase.id,
                idempotency_key=idempotency_key,
                status="completed",
                attempts=self.options.max_attempts,
            )
        )
        return response

    async def _send_with_retries(
        self,
        run: Run,
        trace: Trace,
        testcase: Testcase,
        idempotency_key: str,
        session_id: str | None = None,
    ) -> TargetResponse:
        last_error: Exception | None = None
        session = session_id or self.sessions.session_for_trace(trace)
        for attempt in range(1, self.options.max_attempts + 1):
            self.store.insert_event(
                TraceEvent(
                    trace_id=trace.id,
                    sequence=100 + attempt,
                    event_type="attempt",
                    metadata={"attempt": attempt, "max_attempts": self.options.max_attempts},
                )
            )
            try:
                return await asyncio.wait_for(
                    self.target.send(testcase.prompt, session=session),
                    timeout=self.options.timeout_seconds,
                )
            except Exception as exc:
                last_error = exc
                self.store.upsert_checkpoint(
                    ExecutionCheckpoint(
                        run_id=run.id,
                        trace_id=trace.id,
                        testcase_id=testcase.id,
                        idempotency_key=idempotency_key,
                        status="retrying" if attempt < self.options.max_attempts else "failed",
                        attempts=attempt,
                        error=str(exc),
                    )
                )
                if attempt < self.options.max_attempts and self.options.retry_backoff_seconds:
                    await asyncio.sleep(self.options.retry_backoff_seconds)
        assert last_error is not None
        raise last_error

    @staticmethod
    def _idempotency_key(run: Run, trace: Trace, testcase: Testcase) -> str:
        payload = f"{run.id}:{trace.id}:{testcase.id}:{testcase.content_hash}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
