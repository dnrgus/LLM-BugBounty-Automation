"""P3.4-4 Large Target / Performance (roadmap v3.4.0 Production Hardening).

Large synthetic target benchmark + runtime regression guards for the
three concrete scaling risks this phase fixes: correlation/resolver.py's
entity resolution (was O(source * live)), findings/dedup.py's exact-key
lookup (was a linear bucket scan per finding), and live/discovery.py's
crawl queue (was unbounded and used list.pop(0), which is itself O(n)
per pop on an ever-growing list).
"""

import asyncio
import time

import httpx

from attack_surface.models import AttackSurfaceItem
from core.models import Finding, FindingStatus
from correlation.resolver import resolve_entities
from findings.dedup import cluster_findings
from live.discovery import discover_target
from scope.policy import PolicyEngine


def _broad_policy() -> PolicyEngine:
    return PolicyEngine(
        {
            "program": "perf-test",
            "scope": {"domains": ["ai.example.com"], "url_patterns": ["https://ai.example.com/*"]},
            "testing": {"automated_scanning": True},
        }
    )


def _source_endpoint(path: str) -> AttackSurfaceItem:
    return AttackSurfaceItem(source_type="source", asset_type="endpoint", location=path, metadata={"method": "GET"})


def _live_endpoint(url: str) -> AttackSurfaceItem:
    return AttackSurfaceItem(source_type="live", asset_type="endpoint", location=url, metadata={"method": "GET"})


def test_resolve_entities_scales_to_thousands_of_routes_on_each_side() -> None:
    # Mostly non-overlapping paths (the worst case for a naive nested
    # scan -- nothing short-circuits early) plus a handful of genuine
    # matches to prove correctness survives the indexing.
    source_items = [_source_endpoint(f"/api/resource-{i}") for i in range(2000)]
    live_items = [_live_endpoint(f"https://ai.example.com/api/other-{i}") for i in range(2000)]
    source_items.append(_source_endpoint("/api/chat"))
    live_items.append(_live_endpoint("https://ai.example.com/api/chat"))

    started = time.monotonic()
    matches = resolve_entities(source_items, live_items)
    elapsed = time.monotonic() - started

    assert elapsed < 3.0, f"resolve_entities took {elapsed:.2f}s for 2000x2000 items -- looks quadratic again"
    assert len(matches) == 1
    assert matches[0].confidence == 0.9


def test_cluster_findings_scales_when_most_findings_share_a_root_cause() -> None:
    # The roadmap's own named common case: many mutation/adaptive
    # variants of a small number of seed testcases -- exactly what the
    # O(1) exact-key lookup targets.
    findings = [
        Finding(
            run_id="run_perf",
            testcase_id=f"SEED-{i % 50}::mutation_{i}",
            title=f"Finding {i % 50}",
            category="prompt_injection",
            status=FindingStatus.CONFIRMED,
            confidence=1.0,
            severity="high",
            evidence_ref="ev",
        )
        for i in range(5000)
    ]

    started = time.monotonic()
    clusters = cluster_findings(findings)
    elapsed = time.monotonic() - started

    assert elapsed < 3.0, f"cluster_findings took {elapsed:.2f}s for 5000 findings / 50 root causes -- looks quadratic again"
    assert len(clusters) == 50
    assert sum(cluster.count for cluster in clusters) == 5000


def test_discover_target_stays_fast_with_a_large_fanout_and_a_bounded_queue() -> None:
    # Every page emits many unique links (typical of a poorly-bounded
    # crawl target) across enough pages that an unbounded queue
    # processed via list.pop(0) -- O(n) per pop -- would visibly
    # compound; the bounded queue (P3.4-4) keeps pop(0)'s list small
    # throughout regardless of how many total links exist.
    def handler(request: httpx.Request) -> httpx.Response:
        page_index = str(request.url).rsplit("/", 1)[-1] or "root"
        links = "".join(f'<a href="/p-{page_index}-{i}"></a>' for i in range(1500))
        return httpx.Response(200, headers={"content-type": "text/html"}, text=f"<html><body>{links}</body></html>")

    transport = httpx.MockTransport(handler)

    started = time.monotonic()
    result = asyncio.run(
        discover_target(
            "https://ai.example.com/root", _broad_policy(), max_pages=15, max_queue_size=300, transport=transport
        )
    )
    elapsed = time.monotonic() - started

    assert elapsed < 5.0, f"discover_target took {elapsed:.2f}s for a 15-page/1500-link-per-page crawl"
    assert len(result.fetched_urls) == 15


def test_discover_target_never_queues_the_same_url_twice(tmp_path) -> None:
    # Two pages linking to the exact same set of URLs must not each
    # re-queue them -- proving the P3.4-4 `queued` dedup actually runs,
    # not just that the crawl eventually terminates.
    shared_links = "".join(f'<a href="/shared-{i}"></a>' for i in range(50))
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(200, headers={"content-type": "text/html"}, text=f"<html><body>{shared_links}</body></html>")

    transport = httpx.MockTransport(handler)
    result = asyncio.run(
        discover_target("https://ai.example.com/a", _broad_policy(), max_pages=52, transport=transport)
    )

    # every shared-N URL, plus the two entry pages, fetched exactly once
    assert len(requested) == len(set(requested))
    assert len(result.fetched_urls) <= 52
