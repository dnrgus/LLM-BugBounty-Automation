"""P3.1-1 Scan Orchestrator (roadmap v3.1.0 Operational Pipeline).

Exercises `run_live_scan_pipeline`, the internal API behind `scan <url>`:
discover -> classify -> select packs -> run packs -> judge/reproduce ->
dedup -> report, all from a single call, using a mocked HTTP transport so
no real network traffic is involved.
"""

import asyncio

import httpx
import pytest

from core.orchestrator import run_live_scan_pipeline
from core.profile import load_profile
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from testcase.loader import load_testcases
from tools.runner import ExternalScanOptions

_LLM_HTML = """
<html>
<head><title>API</title></head>
<body>This is an AI chat assistant endpoint.</body>
</html>
"""

_PLAIN_HTML = "<html><head><title>Plain</title></head><body>nothing interesting here</body></html>"


def _policy() -> PolicyEngine:
    # config/scope.example.yaml scopes ai.example.com/api/* and enables
    # prompt_injection/system_prompt_leak/automated_scanning -- same policy
    # the golden regression baseline (tests/regression/test_golden_baseline.py)
    # exercises against the fake-llm target.
    return PolicyEngine.from_yaml("config/scope.example.yaml")


def _testcases():
    return load_testcases("testcase/suites/basic.yaml")


def _transport(html: str) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/html"}, text=html)

    return httpx.MockTransport(handler)


def _run(url: str, html: str, tmp_path, **kwargs):
    store = SQLiteStore(tmp_path / "live_scan.sqlite")
    profile = load_profile("quick", "config/pipeline.yaml")
    return asyncio.run(
        run_live_scan_pipeline(
            _policy(), _testcases(), store, profile, url, transport=_transport(html), **kwargs
        )
    )


def test_live_scan_discovers_classifies_and_runs_matching_testcase_suite_pack(tmp_path) -> None:
    result = _run(
        "https://ai.example.com/api/",
        _LLM_HTML,
        tmp_path,
        pack_target="fake-llm",
    )
    assert result["mode"] == "live"
    assert result["discovery"]["attack_surface"]["total"] > 0
    assert any(candidate["kind"] == "llm" for candidate in result["classification"])
    assert any(selection["pack_id"] == "llm_core" and selection["selected"] for selection in result["pack_selection"])

    testcase_suite_runs = [run for run in result["pack_runs"] if run["tool_id"] == "testcase_suite"]
    assert len(testcase_suite_runs) == 1
    assert testcase_suite_runs[0]["status"] == "ran"

    # Same seed testcases/policy as the golden baseline's fake-llm run:
    # LLM-SP-001 (system_prompt_leak) confirms, LLM-PI-001 is rejected.
    assert result["finding_count"] == 1
    assert result["clusters"][0]["category"] == "system_prompt_leak"
    assert any(path.endswith("_root_cause_clusters.json") for path in result["reports"])


def test_live_scan_with_no_testcase_suite_match_reports_zero_findings_without_crashing(tmp_path) -> None:
    result = _run("https://ai.example.com/api/", _PLAIN_HTML, tmp_path)
    assert not any(candidate["kind"] in {"llm", "rag", "agent"} for candidate in result["classification"])
    assert not any(run["tool_id"] == "testcase_suite" for run in result["pack_runs"])
    assert result["finding_count"] == 0
    assert result["clusters"] == []


def test_live_scan_result_is_json_serializable(tmp_path) -> None:
    import json

    result = _run("https://ai.example.com/api/", _LLM_HTML, tmp_path, pack_target="fake-llm")
    json.dumps(result)


def test_live_scan_surfaces_katana_discovered_param_endpoint_without_a_manual_flag(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The zero-flag UX goal: the static-HTML crawl (_PLAIN_HTML has no
    query-string links) finds nothing to fuzz on its own, but katana's
    headless/XHR crawl did -- run_live_scan_pipeline must fold that into
    param_endpoints with no --param-endpoint/--endpoints-file passed."""

    async def fake_discover_katana_endpoints(url, policy, *, run_id, target_id, timeout_seconds, headers=None):
        return ["https://ai.example.com/api/search?q=x"]

    async def fake_run_external_tool(tool, target, policy, *, run_id, target_id, timeout_seconds):
        from tools.runner import ToolExecutionResult

        return ToolExecutionResult(tool_id=tool.id, status="ran", detail="fake", findings=[])

    monkeypatch.setattr("live.endpoints.discover_katana_endpoints", fake_discover_katana_endpoints)
    # nuclei_dast=True makes the web_scan pack run nuclei for real; mock it
    # out the same way tests/test_dast_endpoints.py does, so this test only
    # exercises the discovery -> endpoint-registry wiring, not a live scan.
    monkeypatch.setattr("packs.runner.run_external_tool", fake_run_external_tool)

    result = _run(
        "https://ai.example.com/api/",
        _PLAIN_HTML,
        tmp_path,
        scan_options=ExternalScanOptions(nuclei_dast=True),
    )
    assert result["param_endpoints"] == ["https://ai.example.com/api/search?q=x"]
