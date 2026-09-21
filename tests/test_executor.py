import asyncio
from pathlib import Path

import pytest

from core.models import CapabilityProfile, Run, Trace
from executor.runner import Executor, ExecutorOptions
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from targets.base import TargetMetadata, TargetResponse
from testcase.schema import Testcase
from traces.exporter import export_trace


class FlakyTarget:
    def __init__(self, fail_count: int = 1, delay: float = 0.0):
        self.fail_count = fail_count
        self.delay = delay
        self.calls = 0

    async def healthcheck(self) -> bool:
        return True

    async def metadata(self) -> TargetMetadata:
        return TargetMetadata(
            id="flaky",
            kind="llm",
            provider="test",
            name="flaky",
            version="test",
            base_url="https://ai.example.com/api/chat",
        )

    async def capabilities(self) -> CapabilityProfile:
        return CapabilityProfile(chat=True, sessions=True)

    async def send(self, prompt: str, session: str | None = None) -> TargetResponse:
        self.calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.calls <= self.fail_count:
            raise RuntimeError("temporary failure")
        return TargetResponse(prompt=prompt, text="ok", metadata={"session": session})

    async def reset_session(self, session: str | None = None) -> None:
        return None

    async def trace(self, session: str | None = None) -> list:
        return []


def _case() -> Testcase:
    return Testcase(
        id="LLM-TEST-001",
        name="Executor Test",
        category="prompt_injection",
        requires=["chat"],
        prompt="hello",
        judges=["rule"],
    )


def _run_and_trace(store: SQLiteStore) -> tuple[Run, Trace]:
    store.initialize()
    run = Run(target_id="flaky", policy_hash="policy", fingerprint="fingerprint")
    trace = Trace(run_id=run.id, testcase_id="LLM-TEST-001")
    store.insert_run(run)
    store.insert_trace(trace)
    return run, trace


def test_executor_retries_and_records_checkpoint(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "executor.sqlite")
    run, trace = _run_and_trace(store)
    target = FlakyTarget(fail_count=1)
    executor = Executor(
        policy=PolicyEngine.from_yaml("config/scope.example.yaml"),
        target=target,
        store=store,
        options=ExecutorOptions(max_attempts=2),
        target_id="flaky",
    )

    response = asyncio.run(
        executor.execute(run, trace, _case(), "https://ai.example.com/api/chat", idempotency_key="retry-key")
    )

    assert response.text == "ok"
    assert target.calls == 2
    checkpoint = store.get_checkpoint("retry-key")
    assert checkpoint is not None
    assert checkpoint["status"] == "completed"


def test_executor_timeout_marks_checkpoint_failed(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "timeout.sqlite")
    run, trace = _run_and_trace(store)
    executor = Executor(
        policy=PolicyEngine.from_yaml("config/scope.example.yaml"),
        target=FlakyTarget(fail_count=0, delay=0.05),
        store=store,
        options=ExecutorOptions(timeout_seconds=0.001, max_attempts=1),
        target_id="flaky",
    )

    with pytest.raises(TimeoutError):
        asyncio.run(
            executor.execute(run, trace, _case(), "https://ai.example.com/api/chat", idempotency_key="timeout-key")
        )

    checkpoint = store.get_checkpoint("timeout-key")
    assert checkpoint is not None
    assert checkpoint["status"] == "failed"
    assert checkpoint["attempts"] == 1


def test_executor_skips_completed_idempotency_key(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "idempotent.sqlite")
    run, trace = _run_and_trace(store)
    target = FlakyTarget(fail_count=0)
    executor = Executor(
        policy=PolicyEngine.from_yaml("config/scope.example.yaml"),
        target=target,
        store=store,
        options=ExecutorOptions(max_attempts=1),
        target_id="flaky",
    )
    case = _case()

    first = asyncio.run(executor.execute(run, trace, case, "https://ai.example.com/api/chat", "same-key"))
    second = asyncio.run(executor.execute(run, trace, case, "https://ai.example.com/api/chat", "same-key"))

    assert first.text == "ok"
    assert second.metadata["resumed"] is True
    assert target.calls == 1


def test_trace_export_accepts_sqlite_rows(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "trace.sqlite")
    run, trace = _run_and_trace(store)
    target = FlakyTarget(fail_count=0)
    executor = Executor(
        policy=PolicyEngine.from_yaml("config/scope.example.yaml"),
        target=target,
        store=store,
        options=ExecutorOptions(max_attempts=1),
        target_id="flaky",
    )
    asyncio.run(executor.execute(run, trace, _case(), "https://ai.example.com/api/chat", "export-key"))

    output = export_trace(tmp_path / "trace.json", store.list_events(trace.id))
    assert output.exists()
    assert "scope_check" in output.read_text(encoding="utf-8")
