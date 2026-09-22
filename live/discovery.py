from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

from attack_surface.models import AttackSurfaceItem
from scope.policy import PolicyEngine

_LINK_RE = re.compile(r'<a\b[^>]*href=["\']([^"\']+)["\']', re.IGNORECASE)
_SCRIPT_RE = re.compile(r'<script\b[^>]*src=["\']([^"\']+)["\']', re.IGNORECASE)
_FORM_ACTION_RE = re.compile(r'<form\b[^>]*action=["\']([^"\']*)["\']', re.IGNORECASE)
_PASSWORD_INPUT_RE = re.compile(r'<input\b[^>]*type=["\']password["\']', re.IGNORECASE)
_TITLE_RE = re.compile(r"<title[^>]*>([^<]*)</title>", re.IGNORECASE)
_API_PATH_RE = re.compile(r'["\'](/api/[a-zA-Z0-9_\-/]+)["\']')
_WS_URL_RE = re.compile(r'["\'](wss?://[^"\']+)["\']')
_SOURCEMAP_RE = re.compile(r"//#\s*sourceMappingURL=(\S+)")
_AI_HINT_RE = re.compile(r"(?i)\b(chat|assistant|completion|generate|rag|retrieval|agent|copilot)\b")


@dataclass
class DiscoveryResult:
    base_url: str
    items: list[AttackSurfaceItem] = field(default_factory=list)
    fetched_urls: list[str] = field(default_factory=list)
    skipped_out_of_scope: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "base_url": self.base_url,
            "fetched_urls": self.fetched_urls,
            "skipped_out_of_scope": self.skipped_out_of_scope,
            "errors": self.errors,
            "attack_surface": {
                "total": len(self.items),
                "items": [item.to_dict() for item in self.items],
            },
        }


async def discover_target(
    base_url: str,
    policy: PolicyEngine,
    max_pages: int = 5,
    timeout_seconds: float = 10.0,
    transport: httpx.AsyncBaseTransport | None = None,
    max_queue_size: int = 1000,
) -> DiscoveryResult:
    """LIVE MODE entrypoint (design doc section 6): observation and
    collection only, never vulnerability testing.

    Safety boundary (doc's own words): "Discovery 단계는 destructive
    payload, SQLi/XSS/Prompt Injection을 보내지 않는다" -- this function
    only ever issues GET requests, with no attacker-controlled content in
    the request. Every URL, including ones discovered mid-crawl (links,
    script srcs), is re-validated against Scope/Policy before it is
    fetched; out-of-scope URLs are recorded in skipped_out_of_scope and
    never touched.

    max_queue_size (P3.4-4, roadmap v3.4.0 Production Hardening): only
    `max_pages` pages are ever *fetched*, but a single large or
    adversarial page can link to far more URLs than that -- without a
    cap, `to_visit` would grow without bound purely from queuing links
    that will never actually be reached. Once the queue hits this size,
    further newly-discovered links are simply not queued (they're
    reachable through other means if they matter; this bounds memory,
    not correctness for a normal-sized target well under the cap). A
    URL already queued (or visited) is also never queued a second time,
    which a densely cross-linked site would otherwise do repeatedly.
    """
    result = DiscoveryResult(base_url=base_url)
    to_visit = [base_url]
    queued: set[str] = {base_url}
    visited: set[str] = set()

    async with httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=True, transport=transport) as client:
        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            if url in visited:
                continue
            if not _allow(policy, result, url):
                continue
            visited.add(url)

            try:
                response = await client.get(url)
            except httpx.HTTPError as exc:
                result.errors.append(f"{url}: {exc}")
                continue
            result.fetched_urls.append(url)

            content_type = response.headers.get("content-type", "")
            _record_fingerprint(result, url, response, content_type)
            if "html" not in content_type:
                continue

            text = response.text
            _record_forms(result, url, text)
            _record_ai_hints(result, url, text)

            for link in _LINK_RE.findall(text):
                absolute = urljoin(url, link)
                if absolute in visited or absolute in queued:
                    continue
                # Scope config, not same-origin-ness, is the sole authority
                # on whether a discovered link gets followed -- a program's
                # scope legitimately may span multiple domains/subdomains.
                if not _allow(policy, result, absolute):
                    continue
                if len(to_visit) >= max_queue_size:
                    continue
                to_visit.append(absolute)
                queued.add(absolute)
            for script_src in _SCRIPT_RE.findall(text):
                await _analyze_js(client, policy, result, urljoin(url, script_src))

    return result


def _allow(policy: PolicyEngine, result: DiscoveryResult, url: str) -> bool:
    decision = policy.validate_url(url)
    if not decision.allowed:
        result.skipped_out_of_scope.append(url)
        return False
    return True


def _record_fingerprint(result: DiscoveryResult, url: str, response: httpx.Response, content_type: str) -> None:
    title_match = _TITLE_RE.search(response.text) if "html" in content_type else None
    header_names = {name.lower() for name in response.headers.keys()}
    result.items.append(
        AttackSurfaceItem(
            source_type="live",
            asset_type="endpoint",
            location=url,
            metadata={
                "method": "GET",
                "status_code": response.status_code,
                "server": response.headers.get("server"),
                "content_type": content_type,
                "title": title_match.group(1).strip() if title_match else None,
            },
            confidence=0.6,
            evidence_refs=[url],
            correlation_keys=[f"GET:{urlparse(url).path or '/'}"],
        )
    )
    if "set-cookie" in header_names:
        result.items.append(
            AttackSurfaceItem(
                source_type="live", asset_type="auth", location=url,
                metadata={"hint": "set-cookie"}, confidence=0.4, evidence_refs=[url],
            )
        )
    if "www-authenticate" in header_names:
        result.items.append(
            AttackSurfaceItem(
                source_type="live", asset_type="auth", location=url,
                metadata={"hint": "www-authenticate", "value": response.headers.get("www-authenticate")},
                confidence=0.6, evidence_refs=[url],
            )
        )


def _record_forms(result: DiscoveryResult, url: str, text: str) -> None:
    for action in _FORM_ACTION_RE.findall(text):
        target = urljoin(url, action) if action else url
        result.items.append(
            AttackSurfaceItem(
                source_type="live", asset_type="endpoint", location=target,
                metadata={"method": "FORM", "page": url}, confidence=0.45, evidence_refs=[url],
            )
        )
    if _PASSWORD_INPUT_RE.search(text):
        result.items.append(
            AttackSurfaceItem(
                source_type="live", asset_type="auth", location=url,
                metadata={"hint": "password_form"}, confidence=0.5, evidence_refs=[url],
            )
        )


def _record_ai_hints(result: DiscoveryResult, url: str, text: str) -> None:
    hints = sorted({hint.lower() for hint in _AI_HINT_RE.findall(text)})
    if hints:
        result.items.append(
            AttackSurfaceItem(
                source_type="live", asset_type="llm", location=url,
                metadata={"hints": hints, "page": url}, confidence=0.35, evidence_refs=[url],
            )
        )


async def _analyze_js(
    client: httpx.AsyncClient, policy: PolicyEngine, result: DiscoveryResult, script_url: str
) -> None:
    if not _allow(policy, result, script_url):
        return
    try:
        response = await client.get(script_url)
    except httpx.HTTPError as exc:
        result.errors.append(f"{script_url}: {exc}")
        return
    result.fetched_urls.append(script_url)
    text = response.text

    for path in sorted(set(_API_PATH_RE.findall(text))):
        result.items.append(
            AttackSurfaceItem(
                source_type="live", asset_type="endpoint", location=path,
                metadata={"method": "UNKNOWN", "source": "js", "file": script_url},
                confidence=0.4, evidence_refs=[script_url], correlation_keys=[f"UNKNOWN:{path}"],
            )
        )
    for ws_url in sorted(set(_WS_URL_RE.findall(text))):
        result.items.append(
            AttackSurfaceItem(
                source_type="live", asset_type="websocket", location=ws_url,
                metadata={"file": script_url}, confidence=0.5, evidence_refs=[script_url],
            )
        )
    sourcemap_match = _SOURCEMAP_RE.search(text)
    if sourcemap_match:
        result.items.append(
            AttackSurfaceItem(
                source_type="live", asset_type="secret", location=script_url,
                metadata={
                    "secret_type": "exposed_source_map",
                    "sourcemap": urljoin(script_url, sourcemap_match.group(1)),
                },
                confidence=0.4, evidence_refs=[script_url],
            )
        )
    _record_ai_hints(result, script_url, text)
