"""WP-06: reuse discovered parameterized endpoints for nuclei DAST fuzzing."""

import asyncio

import pytest

from attack_surface.models import AttackSurfaceItem
from core.tool_doctor import ToolStatus
from live.discovery import DiscoveryResult
from live.endpoints import collect_param_endpoints
from packs.registry import AttackPack
from packs.runner import _run_external_tool_pack
from scope.auto import build_auto_scope
from scope.policy import PolicyEngine
from tools.runner import ExternalScanOptions, ToolExecutionResult


def _local_policy() -> PolicyEngine:
    return PolicyEngine(build_auto_scope("http://127.0.0.1:3000"))


def test_collect_param_endpoints_keeps_only_in_scope_query_urls() -> None:
    policy = _local_policy()
    discovery = DiscoveryResult(
        base_url="http://127.0.0.1:3000",
        fetched_urls=[
            "http://127.0.0.1:3000/",  # no query -> skip
            "http://127.0.0.1:3000/rest/products/search?q=x",  # keep
            "http://127.0.0.1:3000/rest/products/search?q=x",  # dupe -> skip
            "https://evil.example.com/steal?q=1",  # out of scope -> skip
        ],
        items=[
            AttackSurfaceItem(source_type="live", asset_type="endpoint", location="http://127.0.0.1:3000/api/F?id=1"),
        ],
    )
    endpoints = collect_param_endpoints(discovery, policy)
    assert endpoints == [
        "http://127.0.0.1:3000/rest/products/search?q=x",
        "http://127.0.0.1:3000/api/F?id=1",
    ]


def test_collect_param_endpoints_includes_scope_valid_seeds() -> None:
    policy = _local_policy()
    discovery = DiscoveryResult(base_url="http://127.0.0.1:3000", fetched_urls=[], items=[])
    seeds = [
        "http://127.0.0.1:3000/rest/products/search?q=test",  # in scope, kept
        "http://127.0.0.1:3000/rest/no-query",                # seed w/o query still kept
        "https://evil.example.com/x?q=1",                     # out of scope, dropped
    ]
    endpoints = collect_param_endpoints(discovery, policy, seeds=seeds)
    assert endpoints == [
        "http://127.0.0.1:3000/rest/products/search?q=test",
        "http://127.0.0.1:3000/rest/no-query",
    ]


def test_seeds_come_before_discovered_and_dedupe() -> None:
    policy = _local_policy()
    shared = "http://127.0.0.1:3000/rest/products/search?q=test"
    discovery = DiscoveryResult(base_url="http://127.0.0.1:3000", fetched_urls=[shared], items=[])
    endpoints = collect_param_endpoints(discovery, policy, seeds=[shared])
    assert endpoints == [shared]  # deduped, single entry


def test_dast_pack_runs_nuclei_against_the_param_endpoint_list(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    async def fake_run_external_tool(tool, target, policy, *, run_id, target_id, timeout_seconds):
        captured["command"] = tool.build_command(target)
        captured["timeout"] = timeout_seconds
        return ToolExecutionResult(tool_id=tool.id, status="ran", detail="fake", findings=[])

    monkeypatch.setattr("packs.runner.run_external_tool", fake_run_external_tool)

    def available(name: str) -> ToolStatus:
        return ToolStatus(name=name, available=True, path=f"/usr/bin/{name}", version=None, status="ok")

    options = ExternalScanOptions(
        nuclei_dast=True,
        tool_timeout=321.0,
        param_endpoints=("http://127.0.0.1:3000/rest/products/search?q=x",),
    )
    result = asyncio.run(
        _run_external_tool_pack(
            "web_scan", "nuclei", {}, available, _local_policy(), "http://127.0.0.1:3000", options
        )
    )

    assert result.status == "ran"
    command = captured["command"]
    assert "-l" in command  # scanned the endpoint list, not just -u base
    assert "-dast" in command
    assert captured["timeout"] == 321.0


def test_web_scan_pack_uses_attackpack_import() -> None:
    # Guards the module wiring the pack test depends on.
    assert AttackPack(
        id="web_scan", name="Web", applies_to=("web",), testing_categories=("automated_scanning",),
        estimated_request_cost=1, tool_ids=("nuclei",),
    ).id == "web_scan"
