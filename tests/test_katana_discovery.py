"""Auto endpoint/parameter discovery via katana (roadmap: `bugbounty scan
<url>` alone should find an SPA's fetch/XHR-only endpoints, e.g. Juice
Shop's /rest/products/search?q=, without a manual --param-endpoint)."""

import asyncio

import pytest

from core.models import Endpoint
from live.discovery import DiscoveryResult
from live.endpoints import collect_param_endpoints, discover_katana_endpoints
from scope.auto import build_auto_scope
from scope.policy import PolicyEngine
from tools.adapters.discovery.katana import KatanaAdapter
from tools.katana import make_katana_tool
from tools.runner import ToolExecutionResult


def _local_policy() -> PolicyEngine:
    return PolicyEngine(build_auto_scope("http://127.0.0.1:3000"))


def test_katana_command_enables_headless_xhr_and_js_crawl() -> None:
    tool = make_katana_tool(headers={"Authorization": "Bearer t"})
    command = tool.build_command("http://127.0.0.1:3000")
    assert command[0] == "katana"
    assert "-u" in command and "http://127.0.0.1:3000" in command
    assert "-hl" in command
    assert "-xhr-extraction" in command
    assert "-jc" in command
    assert "-H" in command and "Authorization: Bearer t" in command


def test_katana_adapter_parses_xhr_records_and_accepts_version_kwarg() -> None:
    records = [
        {
            "request": {"endpoint": "http://127.0.0.1:3000/rest/products/search?q=", "method": "GET"},
            "response": {"status_code": 200},
        }
    ]
    endpoints = KatanaAdapter().parse(records, run_id="run1", target_id="t1", version="1.0.0")
    assert len(endpoints) == 1
    assert endpoints[0].url == "http://127.0.0.1:3000/rest/products/search?q="


def test_discover_katana_endpoints_degrades_to_empty_when_tool_missing() -> None:
    # katana is not installed in this environment (see `bugbounty doctor`);
    # run_external_tool's own not-installed path must return [] rather than
    # raising, so a scan without katana on PATH still completes.
    endpoints = asyncio.run(
        discover_katana_endpoints(
            "http://127.0.0.1:3000",
            _local_policy(),
            run_id="run1",
            target_id="live_scan",
            timeout_seconds=5.0,
        )
    )
    assert endpoints == []


def test_discover_katana_endpoints_returns_urls_from_a_successful_run(monkeypatch: pytest.MonkeyPatch) -> None:
    found = [Endpoint(run_id="run1", target_id="live_scan", url="http://127.0.0.1:3000/rest/products/search?q=", method="GET", source="katana")]

    async def fake_run_external_tool(tool, target, policy, *, run_id, target_id, timeout_seconds):
        return ToolExecutionResult(tool_id="katana", status="ran", detail="fake", findings=found)

    monkeypatch.setattr("live.endpoints.run_external_tool", fake_run_external_tool)

    endpoints = asyncio.run(
        discover_katana_endpoints(
            "http://127.0.0.1:3000",
            _local_policy(),
            run_id="run1",
            target_id="live_scan",
            timeout_seconds=5.0,
        )
    )
    assert endpoints == ["http://127.0.0.1:3000/rest/products/search?q="]


def test_katana_discovered_query_url_flows_into_the_param_endpoint_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """The zero-flag path: a static-HTML crawl finds nothing with a query
    string, but katana's XHR capture did -- collect_param_endpoints must
    still surface it for nuclei DAST fuzzing, exactly as if it had been
    passed via --param-endpoint."""
    policy = _local_policy()
    discovery = DiscoveryResult(base_url="http://127.0.0.1:3000", fetched_urls=["http://127.0.0.1:3000/"], items=[])

    katana_found = ["http://127.0.0.1:3000/rest/products/search?q="]
    discovery.fetched_urls.extend(katana_found)

    endpoints = collect_param_endpoints(discovery, policy)
    assert endpoints == ["http://127.0.0.1:3000/rest/products/search?q="]
