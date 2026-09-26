"""WP-06: reuse discovery output as the shared endpoint registry (§8).

Instead of each scanner re-crawling, collect the parameterized URLs that
discovery already found (and already validated in-scope) so nuclei DAST can
fuzz their parameters. Every URL is re-validated against Policy/Scope here
too, so nothing that slipped in via a merged AttackSurfaceItem is fuzzed
without a scope check (§13).
"""

from __future__ import annotations

from urllib.parse import urlparse

from live.discovery import DiscoveryResult
from scope.policy import PolicyEngine


def collect_param_endpoints(discovery: DiscoveryResult, policy: PolicyEngine) -> list[str]:
    """Return in-scope http(s) URLs that carry a query string, deduped and
    order-preserving. These are the candidates worth DAST parameter fuzzing.
    """
    candidates: list[str] = list(discovery.fetched_urls)
    candidates.extend(item.location for item in discovery.items if isinstance(item.location, str))

    seen: set[str] = set()
    endpoints: list[str] = []
    for url in candidates:
        if not url.startswith(("http://", "https://")):
            continue
        if not urlparse(url).query:
            continue
        if url in seen:
            continue
        if not policy.validate_url(url).allowed:
            continue
        seen.add(url)
        endpoints.append(url)
    return endpoints
