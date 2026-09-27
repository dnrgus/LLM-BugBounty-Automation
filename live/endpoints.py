"""WP-06: reuse discovery output as the shared endpoint registry (§8).

Instead of each scanner re-crawling, collect the parameterized URLs that
discovery already found (and already validated in-scope) so nuclei DAST can
fuzz their parameters. Every URL is re-validated against Policy/Scope here
too, so nothing that slipped in via a merged AttackSurfaceItem is fuzzed
without a scope check (§13).
"""

from __future__ import annotations

from collections.abc import Sequence
from urllib.parse import urlparse

from live.discovery import DiscoveryResult
from scope.policy import PolicyEngine
from tools.katana import make_katana_tool
from tools.runner import run_external_tool


async def discover_katana_endpoints(
    url: str,
    policy: PolicyEngine,
    *,
    run_id: str,
    target_id: str,
    timeout_seconds: float,
    headers: dict[str, str] | None = None,
) -> list[str]:
    """Headless-crawl `url` with katana to find endpoints a static-HTML
    crawl (live.discovery.discover_target) can't -- an SPA's fetch/XHR
    calls, like Juice Shop's product grid firing
    /rest/products/search?q= on page load with no user interaction.

    Returns raw URLs (with or without a query string); the caller folds
    them into DiscoveryResult.fetched_urls so they get the exact same
    require_query + scope filtering as any other discovered URL, in
    collect_param_endpoints below. When katana isn't installed,
    run_external_tool's own skipped_tool_not_installed path returns no
    findings, so this degrades to [] instead of raising (see
    `bugbounty doctor`).
    """
    result = await run_external_tool(
        make_katana_tool(headers=headers),
        url,
        policy,
        run_id=run_id,
        target_id=target_id,
        timeout_seconds=timeout_seconds,
    )
    return [endpoint.url for endpoint in result.findings]


def collect_param_endpoints(
    discovery: DiscoveryResult, policy: PolicyEngine, seeds: Sequence[str] = ()
) -> list[str]:
    """Return in-scope http(s) URLs worth DAST parameter fuzzing, deduped and
    order-preserving.

    Two sources: (1) URLs discovery observed that carry a query string, and
    (2) explicit `seeds` the operator supplied (--param-endpoint /
    --endpoints-file). Seeds are trusted as intentional fuzz targets so the
    query-string filter is not applied to them, but they still must pass
    Policy/Scope -- the tool never fuzzes a URL the scope doesn't allow (§13),
    even one the user typed. Seeds come first so operator intent is honored.
    """
    seen: set[str] = set()
    endpoints: list[str] = []

    def _add(url: str, require_query: bool) -> None:
        if not url.startswith(("http://", "https://")):
            return
        if require_query and not urlparse(url).query:
            return
        if url in seen:
            return
        if not policy.validate_url(url).allowed:
            return
        seen.add(url)
        endpoints.append(url)

    for seed in seeds:
        _add(seed, require_query=False)
    for url in discovery.fetched_urls:
        _add(url, require_query=True)
    for item in discovery.items:
        if isinstance(item.location, str):
            _add(item.location, require_query=True)
    return endpoints
