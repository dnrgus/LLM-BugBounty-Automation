"""P4.1-E Finding/Reproducer/Report integration (roadmap v4.1.0 Dynamic
Validation Expansion): wires endpoint/auth/dataflow validators into
validation/executor.py's dispatch, producing Findings via
validation/finding_adapter.py.
"""

import asyncio

import httpx

from attack_surface.models import AttackSurfaceItem
from core.models import FindingStatus
from core.orchestrator import run_reproduce_finding
from correlation.resolver import resolve_entities
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from validation.auth_validator import ANONYMOUS_CONTEXT, AuthContext
from validation.contract import ValidationResult, ValidationStatus, ValidationTask
from validation.dataflow_validator import DataflowInjectionPoint
from validation.executor import run_auth_validation, run_dataflow_validation, run_endpoint_validation
from validation.finding_adapter import finding_from_validation_result
from validation.planner import ValidationPlan


def _policy() -> PolicyEngine:
    return PolicyEngine(
        {
            "program": "dispatch-test",
            "scope": {"domains": ["ai.example.com"], "url_patterns": ["https://ai.example.com/*"]},
            "testing": {"automated_scanning": True},
        }
    )


def _endpoint_match(url: str = "https://ai.example.com/api/resource"):
    source = AttackSurfaceItem(source_type="source", asset_type="endpoint", location="/api/resource", metadata={"method": "GET"})
    live = AttackSurfaceItem(source_type="live", asset_type="endpoint", location=url, metadata={"method": "GET"})
    return source, resolve_entities([source], [live])[0]


def test_run_endpoint_validation_confirms_reachable_candidate(tmp_path) -> None:
    store = SQLiteStore(tmp_path / "dispatch.sqlite")
    store.initialize()
    item, match = _endpoint_match()
    plan = ValidationPlan(item.id, "endpoint", "executable", "matched live endpoint")

    outcome = asyncio.run(
        run_endpoint_validation(
            item, plan, match, _policy(), store, "run-1", transport=httpx.MockTransport(lambda r: httpx.Response(200))
        )
    )

    assert outcome.status == "ran"
    assert outcome.correlated_findings
    finding = outcome.correlated_findings[0].finding
    assert finding.status == FindingStatus.CONFIRMED
    assert finding.origin == ["static", "dynamic"]
    assert finding.static_candidate_id == item.id
    assert finding.validation_status == "confirmed"
    assert finding.validation_task_ids
    reloaded = store.get_finding(finding.id)
    assert reloaded.static_candidate_id == item.id
    assert reloaded.validation_status == "confirmed"


def test_run_endpoint_validation_not_run_when_not_executable(tmp_path) -> None:
    store = SQLiteStore(tmp_path / "dispatch.sqlite")
    store.initialize()
    item, match = _endpoint_match()
    plan = ValidationPlan(item.id, "endpoint", "review_only", "no good match")

    outcome = asyncio.run(
        run_endpoint_validation(item, plan, match, _policy(), store, "run-1", transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    )
    assert outcome.status == "not_run"
    assert outcome.correlated_findings == []


def test_run_endpoint_validation_blocked_out_of_scope_produces_no_finding(tmp_path) -> None:
    store = SQLiteStore(tmp_path / "dispatch.sqlite")
    store.initialize()
    item, match = _endpoint_match(url="https://evil.example.net/api/resource")
    plan = ValidationPlan(item.id, "endpoint", "executable", "matched live endpoint")

    outcome = asyncio.run(
        run_endpoint_validation(item, plan, match, _policy(), store, "run-1", transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    )
    assert outcome.status == "ran"
    assert outcome.correlated_findings == []


def test_run_auth_validation_confirmed_produces_high_severity_finding(tmp_path) -> None:
    store = SQLiteStore(tmp_path / "dispatch.sqlite")
    store.initialize()
    item, match = _endpoint_match()
    control = AuthContext(id="session_a", principal_label="user A", headers={"Authorization": "Bearer x"})

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "application/json"}, text="{}")

    outcome = asyncio.run(
        run_auth_validation(
            item, match, _policy(), control, ANONYMOUS_CONTEXT, store, "run-1",
            transport=httpx.MockTransport(handler),
        )
    )

    assert outcome.correlated_findings
    finding = outcome.correlated_findings[0].finding
    assert finding.status == FindingStatus.CONFIRMED
    assert finding.severity == "high"
    assert finding.validation_status == "confirmed"


def test_run_auth_validation_rejected_when_probe_denied(tmp_path) -> None:
    store = SQLiteStore(tmp_path / "dispatch.sqlite")
    store.initialize()
    item, match = _endpoint_match()
    control = AuthContext(id="session_a", principal_label="user A", headers={"Authorization": "Bearer x"})

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("Authorization"):
            return httpx.Response(200, headers={"content-type": "application/json"}, text="{}")
        return httpx.Response(403)

    outcome = asyncio.run(
        run_auth_validation(
            item, match, _policy(), control, ANONYMOUS_CONTEXT, store, "run-1",
            transport=httpx.MockTransport(handler),
        )
    )

    finding = outcome.correlated_findings[0].finding
    assert finding.status == FindingStatus.REJECTED
    assert finding.validation_status == "rejected"


def test_run_dataflow_validation_reflected_is_review_only_finding(tmp_path) -> None:
    store = SQLiteStore(tmp_path / "dispatch.sqlite")
    store.initialize()
    item = AttackSurfaceItem(
        source_type="source", asset_type="dataflow", location="app.py:42",
        metadata={"sink_type": "xss_reflection"},
    )

    def handler(request: httpx.Request) -> httpx.Response:
        token = request.url.params.get("q")
        return httpx.Response(200, text=f"echo {token}")

    outcome = asyncio.run(
        run_dataflow_validation(
            item, _policy(), DataflowInjectionPoint("query", "q"), "https://ai.example.com/search", store, "run-1",
            transport=httpx.MockTransport(handler),
        )
    )

    assert outcome.correlated_findings
    finding = outcome.correlated_findings[0].finding
    assert finding.status == FindingStatus.CANDIDATE
    assert finding.validation_status == "review_only"
    assert finding.category == "dataflow"


def test_run_dataflow_validation_destructive_sink_still_produces_review_only(tmp_path) -> None:
    store = SQLiteStore(tmp_path / "dispatch.sqlite")
    store.initialize()
    item = AttackSurfaceItem(
        source_type="source", asset_type="dataflow", location="app.py:99",
        metadata={"sink_type": "sql_injection"},
    )

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must never send a request for a destructive sink type")

    outcome = asyncio.run(
        run_dataflow_validation(
            item, _policy(), DataflowInjectionPoint("query", "q"), "https://ai.example.com/search", store, "run-1",
            transport=httpx.MockTransport(handler),
        )
    )

    finding = outcome.correlated_findings[0].finding
    assert finding.validation_status == "review_only"


def test_finding_from_validation_result_returns_none_for_non_terminal_states() -> None:
    task = ValidationTask(candidate_id="AS-1", validator_type="endpoint")
    for status in (ValidationStatus.PLANNED, ValidationStatus.EXECUTABLE, ValidationStatus.RUNNING, ValidationStatus.BLOCKED):
        result = ValidationResult(task_id=task.id, status=status, confidence=0.5)
        assert finding_from_validation_result("run-1", task, result, "ev-1", "https://ai.example.com/x") is None


def test_finding_from_validation_result_review_only_maps_to_candidate_status() -> None:
    task = ValidationTask(candidate_id="AS-1", validator_type="dataflow")
    result = ValidationResult(task_id=task.id, status=ValidationStatus.REVIEW_ONLY, confidence=0.5)
    finding = finding_from_validation_result("run-1", task, result, "ev-1", "https://ai.example.com/x")
    assert finding is not None
    assert finding.status == FindingStatus.CANDIDATE
    assert finding.validation_status == "review_only"


def test_run_reproduce_finding_reports_validation_findings_as_unsupported_instead_of_crashing(tmp_path) -> None:
    store = SQLiteStore(tmp_path / "dispatch.sqlite")
    store.initialize()
    item, match = _endpoint_match()
    plan = ValidationPlan(item.id, "endpoint", "executable", "matched live endpoint")
    outcome = asyncio.run(
        run_endpoint_validation(item, plan, match, _policy(), store, "run-1", transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    )
    finding = outcome.correlated_findings[0].finding

    result = asyncio.run(run_reproduce_finding(_policy(), [], store, finding.id, target_kind="fake-llm"))

    assert result["reproduction"]["type"] == "validation"
    assert result["reproduction"]["status"] == "unsupported"


def test_dynamic_validation_outcome_to_dict_is_json_serializable_for_endpoint(tmp_path) -> None:
    import json

    store = SQLiteStore(tmp_path / "dispatch.sqlite")
    store.initialize()
    item, match = _endpoint_match()
    plan = ValidationPlan(item.id, "endpoint", "executable", "matched live endpoint")
    outcome = asyncio.run(
        run_endpoint_validation(item, plan, match, _policy(), store, "run-1", transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    )
    json.dumps(outcome.to_dict())
