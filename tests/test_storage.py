from pathlib import Path

from core.models import (
    FindingStatus,
    RequestRecord,
    ResponseRecord,
    Run,
    StoredTestcase,
    Target,
    Trace,
    TraceEvent,
)
from storage.sqlite import SQLiteStore


def test_storage_crud_and_trace_ordering(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "phase1.sqlite")
    store.initialize()

    store.insert_target(
        Target(
            id="target_1",
            kind="llm",
            base_url="https://ai.example.com/api/chat",
            capabilities={"chat": True},
        )
    )
    run = Run(target_id="target_1", policy_hash="policy", fingerprint="fingerprint")
    store.insert_run(run)
    store.insert_testcase(
        StoredTestcase(
            id="LLM-PI-001",
            name="Basic Instruction Override",
            category="prompt_injection",
            content_hash="hash",
        )
    )
    trace = Trace(run_id=run.id, testcase_id="LLM-PI-001")
    store.insert_trace(trace)
    store.insert_event(TraceEvent(trace_id=trace.id, sequence=2, event_type="final_response"))
    store.insert_event(TraceEvent(trace_id=trace.id, sequence=1, event_type="llm_call"))

    request = RequestRecord(
        run_id=run.id,
        trace_id=trace.id,
        testcase_id="LLM-PI-001",
        prompt_hash="hash",
        metadata={"attempt": 1},
    )
    store.insert_request(request)
    store.insert_response(
        ResponseRecord(
            request_id=request.id,
            trace_id=trace.id,
            status_code=200,
            token_count=5,
        )
    )

    events = store.list_events(trace.id)
    assert [row["event_type"] for row in events] == ["llm_call", "final_response"]

    with store.connect() as conn:
        assert conn.execute("select count(*) from targets").fetchone()[0] == 1
        assert conn.execute("select count(*) from testcases").fetchone()[0] == 1
        assert conn.execute("select count(*) from requests").fetchone()[0] == 1
        assert conn.execute("select count(*) from responses").fetchone()[0] == 1


def test_reproduction_success_rate() -> None:
    from core.models import Reproduction

    repro = Reproduction(
        finding_id="finding_1",
        attempts=5,
        successes=3,
        control_passed=True,
        status=FindingStatus.CONFIRMED,
    )
    assert repro.success_rate == 0.6

