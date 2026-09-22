"""P3.4-2 Cancellation / Timeout / Backpressure (roadmap v3.4.0 Production Hardening)."""

import asyncio
from pathlib import Path

import pytest

from core.cancel import BoundedConcurrency, CancellationToken, OperationCancelled
from core.models import Run, Trace
from core.orchestrator import run_sample_pipeline
from executor.runner import Executor
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from targets.fake import FakeLLMTarget
from testcase.loader import load_testcases
from tools.runner import ExternalTool, run_external_tool


def _policy() -> PolicyEngine:
    return PolicyEngine.from_yaml("config/scope.example.yaml")


def _testcases():
    return load_testcases("testcase/suites/basic.yaml")


def test_cancellation_token_starts_uncancelled() -> None:
    token = CancellationToken()
    assert token.is_cancelled is False
    token.raise_if_cancelled()  # must not raise


def test_cancellation_token_raises_after_cancel() -> None:
    token = CancellationToken()
    token.cancel("stop now")
    assert token.is_cancelled is True
    with pytest.raises(OperationCancelled):
        token.raise_if_cancelled()


def test_bounded_concurrency_with_no_limit_is_unbounded() -> None:
    async def _run():
        bc = BoundedConcurrency(None)
        async with bc:
            async with bc:
                assert bc.in_flight == 2
        return bc.max_in_flight_seen

    assert asyncio.run(_run()) == 2


def test_bounded_concurrency_caps_concurrent_tasks_at_the_limit() -> None:
    async def _run():
        bc = BoundedConcurrency(2)

        async def worker():
            async with bc:
                await asyncio.sleep(0.05)

        await asyncio.gather(*(worker() for _ in range(6)))
        return bc.max_in_flight_seen

    assert asyncio.run(_run()) == 2


def test_executor_raises_operation_cancelled_before_ever_calling_the_target(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "cancel.sqlite")
    store.initialize()

    class RaisesIfCalled(FakeLLMTarget):
        async def send(self, prompt, session=None):
            raise AssertionError("target.send() must never be called once cancelled")

    token = CancellationToken()
    token.cancel("stop")
    executor = Executor(policy=_policy(), target=RaisesIfCalled(), store=store, target_id="fake-llm", cancellation=token)
    run = Run(target_id="fake-llm", policy_hash=_policy().policy_hash, fingerprint="cancel-test")
    store.insert_run(run)
    trace = Trace(run_id=run.id, testcase_id="t1")
    store.insert_trace(trace)
    case = _testcases()[0]

    with pytest.raises(OperationCancelled):
        asyncio.run(executor.execute(run=run, trace=trace, testcase=case, url="https://ai.example.com/api/chat"))


def test_executor_enforces_concurrency_limit_from_scope_config(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "concurrency.sqlite")
    store.initialize()
    policy = PolicyEngine(
        {
            "program": "concurrency-test",
            "scope": {"domains": ["ai.example.com"], "url_patterns": ["https://ai.example.com/*"]},
            "testing": {"automated_scanning": True, "prompt_injection": True},
            "limits": {"concurrency": 1},
        }
    )
    executor = Executor(policy=policy, target=FakeLLMTarget(), store=store, target_id="fake-llm")
    assert executor._concurrency.limit == 1

    run = Run(target_id="fake-llm", policy_hash=policy.policy_hash, fingerprint="concurrency-test")
    store.insert_run(run)
    case = _testcases()[0]

    async def _one():
        trace = Trace(run_id=run.id, testcase_id=case.id)
        store.insert_trace(trace)
        await executor.execute(run=run, trace=trace, testcase=case, url="https://ai.example.com/api/chat")

    async def _run_all():
        await asyncio.gather(*(_one() for _ in range(4)))

    asyncio.run(_run_all())
    assert executor._concurrency.max_in_flight_seen == 1


def test_run_sample_pipeline_stops_immediately_when_already_cancelled(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "cancel_pipeline.sqlite")
    token = CancellationToken()
    token.cancel("user requested stop")

    result = asyncio.run(
        run_sample_pipeline(_policy(), _testcases(), store, target_kind="fake-llm", cancellation=token)
    )

    assert result["cancelled"] is True
    assert result["executed_testcases"] == []


def test_run_sample_pipeline_cancellation_marks_a_resumable_run_as_cancelled(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "cancel_resume.sqlite")
    token = CancellationToken()
    token.cancel("user requested stop")

    asyncio.run(
        run_sample_pipeline(
            _policy(), _testcases(), store, target_kind="fake-llm", resume_run_id="run_cancel_1", cancellation=token
        )
    )

    with store.connect() as conn:
        row = conn.execute("select status from run_state where run_id = ?", ("run_cancel_1",)).fetchone()
    assert row["status"] == "cancelled"

    # a cancelled run is still resumable later
    fresh_token = CancellationToken()
    second = asyncio.run(
        run_sample_pipeline(
            _policy(), _testcases(), store, target_kind="fake-llm", resume_run_id="run_cancel_1", cancellation=fresh_token
        )
    )
    assert second["executed_testcases"] == ["LLM-PI-001", "LLM-SP-001"]
    assert second["cancelled"] is False


def test_run_sample_pipeline_without_cancellation_is_unaffected(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "no_cancel.sqlite")
    result = asyncio.run(run_sample_pipeline(_policy(), _testcases(), store, target_kind="fake-llm"))
    assert result["cancelled"] is False
    assert result["executed_testcases"] == ["LLM-PI-001", "LLM-SP-001"]


def _fixture_sleeping_binary(tmp_path: Path, sleep_seconds: float = 5) -> Path:
    script = tmp_path / "sleepy-tool"
    script.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then echo "sleepy 1.0"; exit 0; fi\n'
        f"sleep {sleep_seconds}\n"
        "echo '[]'\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def test_run_external_tool_cancel_kills_the_subprocess_promptly(tmp_path: Path) -> None:
    from adapters.scanner.nuclei import NucleiAdapter

    binary = _fixture_sleeping_binary(tmp_path)
    tool = ExternalTool(
        id="fixture", binary=str(binary), build_command=lambda target: [str(binary), "-u", target],
        parse_output=lambda stdout: [], normalizer=NucleiAdapter(),
    )
    token = CancellationToken()

    async def _run():
        cancel_soon = asyncio.get_event_loop().call_later(0.2, token.cancel, "stop the scan")
        try:
            return await run_external_tool(
                tool, "https://ai.example.com/api/", _policy(), run_id="run_1", target_id="t",
                timeout_seconds=30, cancellation=token,
            )
        finally:
            cancel_soon.cancel()

    result = asyncio.run(_run())
    assert result.status == "cancelled"


def test_run_external_tool_without_cancellation_still_behaves_as_before(tmp_path: Path) -> None:
    from adapters.scanner.nuclei import NucleiAdapter

    binary = _fixture_sleeping_binary(tmp_path, sleep_seconds=5)
    tool = ExternalTool(
        id="fixture", binary=str(binary), build_command=lambda target: [str(binary), "-u", target],
        parse_output=lambda stdout: [], normalizer=NucleiAdapter(),
    )
    result = asyncio.run(
        run_external_tool(tool, "https://ai.example.com/api/", _policy(), run_id="run_1", target_id="t", timeout_seconds=0.3)
    )
    assert result.status == "timeout"
