"""P4.1-B Endpoint Validator (roadmap v4.1.0 Dynamic Validation Expansion)."""

import asyncio

import httpx

from scope.policy import PolicyEngine
from validation.endpoint_validator import normalize_probe_methods, validate_endpoint


def _policy() -> PolicyEngine:
    return PolicyEngine(
        {
            "program": "endpoint-validator-test",
            "scope": {"domains": ["ai.example.com"], "url_patterns": ["https://ai.example.com/*"]},
            "testing": {"automated_scanning": True},
        }
    )


# --- method normalization -------------------------------------------------


def test_normalize_probe_methods_always_includes_get() -> None:
    assert "GET" in normalize_probe_methods("POST")
    assert normalize_probe_methods("GET") == ["GET"]


def test_normalize_probe_methods_includes_declared_safe_methods() -> None:
    assert normalize_probe_methods("HEAD") == ["GET", "HEAD"]


def test_normalize_probe_methods_never_includes_destructive_verbs() -> None:
    assert normalize_probe_methods("POST") == ["GET"]
    assert normalize_probe_methods("DELETE") == ["GET"]
    assert normalize_probe_methods("GET|POST") == ["GET"]


def test_normalize_probe_methods_drops_route_and_any_placeholder_labels() -> None:
    assert normalize_probe_methods("ROUTE") == ["GET"]
    assert normalize_probe_methods("ANY") == ["GET"]


# --- policy gate ------------------------------------------------------------


def test_validate_endpoint_blocks_out_of_scope_candidate_without_sending_a_request() -> None:
    called = []

    def handler(request: httpx.Request) -> httpx.Response:
        called.append(request)
        return httpx.Response(200)

    evidence = asyncio.run(
        validate_endpoint(
            "https://evil.example.net/x", "GET", _policy(), transport=httpx.MockTransport(handler)
        )
    )
    assert evidence.blocked is True
    assert evidence.observations == []
    assert called == []


# --- integration: public/protected/missing ---------------------------------


def _three_endpoint_handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/public":
        return httpx.Response(200, headers={"content-type": "text/html"}, text="ok")
    if path == "/protected":
        return httpx.Response(401, headers={"content-type": "application/json"})
    return httpx.Response(404)


def test_validate_endpoint_distinguishes_public_protected_and_missing_endpoints() -> None:
    transport = httpx.MockTransport(_three_endpoint_handler)
    policy = _policy()

    public = asyncio.run(validate_endpoint("https://ai.example.com/public", "GET", policy, transport=transport))
    protected = asyncio.run(validate_endpoint("https://ai.example.com/protected", "GET", policy, transport=transport))
    missing = asyncio.run(validate_endpoint("https://ai.example.com/does-not-exist", "GET", policy, transport=transport))

    assert public.observations[0].status_code == 200
    assert protected.observations[0].status_code == 401
    assert missing.observations[0].status_code == 404


def test_validate_endpoint_is_deterministic_for_repeated_calls() -> None:
    transport = httpx.MockTransport(_three_endpoint_handler)
    policy = _policy()
    first = asyncio.run(validate_endpoint("https://ai.example.com/protected", "GET", policy, transport=transport))
    second = asyncio.run(validate_endpoint("https://ai.example.com/protected", "GET", policy, transport=transport))
    assert first.to_dict() == second.to_dict()


# --- regression: trailing slash ---------------------------------------------


def test_validate_endpoint_preserves_trailing_slash_in_the_request_url() -> None:
    requested_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        return httpx.Response(200)

    asyncio.run(
        validate_endpoint(
            "https://ai.example.com/api/chat/", "GET", _policy(), transport=httpx.MockTransport(handler)
        )
    )
    assert requested_urls == ["https://ai.example.com/api/chat/"]


# --- redirect hop policy -----------------------------------------------------


def test_validate_endpoint_follows_in_scope_redirects_and_records_the_chain() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/old":
            return httpx.Response(302, headers={"location": "/new"})
        return httpx.Response(200)

    evidence = asyncio.run(
        validate_endpoint("https://ai.example.com/old", "GET", _policy(), transport=httpx.MockTransport(handler))
    )
    observation = evidence.observations[0]
    assert observation.status_code == 200
    assert observation.redirect_chain == ["https://ai.example.com/new"]
    assert observation.error is None


def test_validate_endpoint_stops_at_an_out_of_scope_redirect_hop() -> None:
    # Cross-origin filter regression: a redirect to a different domain
    # must be recorded, never followed.
    called_hosts = []

    def handler(request: httpx.Request) -> httpx.Response:
        called_hosts.append(request.url.host)
        if request.url.host == "ai.example.com":
            return httpx.Response(302, headers={"location": "https://evil.example.net/steal"})
        return httpx.Response(200)  # would only happen if wrongly followed

    evidence = asyncio.run(
        validate_endpoint("https://ai.example.com/redirect-out", "GET", _policy(), transport=httpx.MockTransport(handler))
    )
    observation = evidence.observations[0]
    assert observation.redirect_chain == ["https://evil.example.net/steal"]
    assert "out of scope" in observation.error
    assert called_hosts == ["ai.example.com"]  # the out-of-scope hop was never actually requested


def test_validate_endpoint_reports_max_redirect_hops_exceeded() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        # Always bounces back to itself -- an infinite redirect loop.
        return httpx.Response(302, headers={"location": "/loop"})

    evidence = asyncio.run(
        validate_endpoint("https://ai.example.com/loop", "GET", _policy(), transport=httpx.MockTransport(handler))
    )
    observation = evidence.observations[0]
    assert observation.status_code is None
    assert observation.error == "max redirect hops exceeded"


def test_validate_endpoint_records_network_errors_without_raising() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    evidence = asyncio.run(
        validate_endpoint("https://ai.example.com/down", "GET", _policy(), transport=httpx.MockTransport(handler))
    )
    observation = evidence.observations[0]
    assert observation.status_code is None
    assert observation.error is not None


def test_endpoint_validation_evidence_to_dict_is_json_serializable() -> None:
    import json

    evidence = asyncio.run(
        validate_endpoint(
            "https://ai.example.com/public", "GET", _policy(), transport=httpx.MockTransport(_three_endpoint_handler)
        )
    )
    json.dumps(evidence.to_dict())
