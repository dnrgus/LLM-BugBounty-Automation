import asyncio

import httpx

from hybrid.correlate import correlate_source_and_live
from live.discovery import discover_target
from scope.policy import PolicyEngine

_HTML = "<html><head><title>Site</title></head><body>hello</body></html>"


def _policy() -> PolicyEngine:
    return PolicyEngine(
        {
            "program": "hybrid-test",
            "scope": {"domains": ["target.example.com"], "url_patterns": ["https://target.example.com/*"]},
            "testing": {"automated_scanning": True},
        }
    )


def _discover_about_page():
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "https://target.example.com/about":
            return httpx.Response(200, headers={"content-type": "text/html"}, text=_HTML)
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    return asyncio.run(discover_target("https://target.example.com/about", _policy(), transport=transport))


def test_correlate_merges_a_route_that_is_also_seen_live() -> None:
    live_result = _discover_about_page()
    result = correlate_source_and_live("tests/fixtures/source/hybrid_app", live_result)

    merged_endpoints = [
        item for item in result.items if item.asset_type == "endpoint" and item.source_type == "merged"
    ]
    assert len(merged_endpoints) == 1
    merged = merged_endpoints[0]
    assert "GET:/about" in merged.correlation_keys
    assert len(merged.provenance) == 2
    assert {p["source_type"] for p in merged.provenance} == {"source", "live"}


def test_correlate_leaves_source_only_findings_unmerged_when_not_seen_live() -> None:
    live_result = _discover_about_page()
    result = correlate_source_and_live("tests/fixtures/source/hybrid_app", live_result)

    admin_route = [item for item in result.items if item.location == "/api/admin/run"]
    assert len(admin_route) == 1
    assert admin_route[0].source_type == "source"

    sinks = [item for item in result.items if item.asset_type == "function"]
    assert sinks
    assert all(item.source_type == "source" for item in sinks)


def test_correlate_boosts_confidence_for_corroborated_endpoints() -> None:
    live_result = _discover_about_page()
    result = correlate_source_and_live("tests/fixtures/source/hybrid_app", live_result)

    merged = next(item for item in result.items if item.asset_type == "endpoint" and item.source_type == "merged")
    source_only_confidence = 0.6  # source/routes.py's own confidence for a route item
    assert merged.confidence > source_only_confidence


def test_correlation_result_to_dict_reports_corroborated_count() -> None:
    import json

    live_result = _discover_about_page()
    result = correlate_source_and_live("tests/fixtures/source/hybrid_app", live_result)
    payload = result.to_dict()
    json.dumps(payload)
    assert payload["attack_surface"]["corroborated_by_both"] == 1
    assert payload["live_base_url"] == "https://target.example.com/about"


def test_correlate_with_no_live_overlap_produces_no_merges() -> None:
    async def _empty_discover():
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        return await discover_target("https://target.example.com/nowhere", _policy(), transport=transport)

    live_result = asyncio.run(_empty_discover())
    result = correlate_source_and_live("tests/fixtures/source/hybrid_app", live_result)
    assert all(item.source_type != "merged" for item in result.items)
