"""P4.1-D Dataflow Validator (roadmap v4.1.0 Dynamic Validation Expansion)."""

import asyncio
import json

import httpx

from scope.policy import PolicyEngine
from validation.contract import ValidationStatus
from validation.dataflow_validator import (
    DataflowInjectionPoint,
    can_safely_probe,
    generate_correlation_token,
    validate_dataflow_correlation,
)


def _policy() -> PolicyEngine:
    return PolicyEngine(
        {
            "program": "dataflow-validator-test",
            "scope": {"domains": ["ai.example.com"], "url_patterns": ["https://ai.example.com/*"]},
            "testing": {"automated_scanning": True},
        }
    )


def test_generate_correlation_token_is_unique_and_marked() -> None:
    first = generate_correlation_token()
    second = generate_correlation_token()
    assert first != second
    assert first.startswith("DFCANARY-")


def test_can_safely_probe_rejects_destructive_sink_types() -> None:
    for sink_type in ("sql_injection", "os_command", "prompt_injection_sink", "ssrf"):
        allowed, reason = can_safely_probe(sink_type, "query")
        assert allowed is False
        assert reason is not None


def test_can_safely_probe_rejects_body_only_injection_locations() -> None:
    allowed, reason = can_safely_probe("xss_reflection", "form_body")
    assert allowed is False
    assert reason is not None


def test_can_safely_probe_allows_safe_sink_and_location() -> None:
    allowed, reason = can_safely_probe("xss_reflection", "query")
    assert allowed is True
    assert reason is None


def test_validate_dataflow_correlation_skips_destructive_sink_without_any_request() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must never send a request for an unsafe sink type")

    result = asyncio.run(
        validate_dataflow_correlation(
            "https://ai.example.com/search", "sql_injection", DataflowInjectionPoint("query", "q"),
            "app.py:42", _policy(), transport=httpx.MockTransport(handler),
        )
    )
    assert result.injected is False
    assert result.skipped_reason is not None
    assert result.status == ValidationStatus.REVIEW_ONLY


def test_validate_dataflow_correlation_blocked_out_of_scope() -> None:
    result = asyncio.run(
        validate_dataflow_correlation(
            "https://evil.example.net/search", "xss_reflection", DataflowInjectionPoint("query", "q"),
            "app.py:42", _policy(), transport=httpx.MockTransport(lambda r: httpx.Response(200)),
        )
    )
    assert result.blocked is True
    assert result.block_reason is not None
    assert result.status == ValidationStatus.BLOCKED


def test_validate_dataflow_correlation_reflected_is_review_only() -> None:
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        token = request.url.params.get("q")
        captured["token"] = token
        return httpx.Response(200, text=f"<p>results for {token}</p>")

    result = asyncio.run(
        validate_dataflow_correlation(
            "https://ai.example.com/search", "xss_reflection", DataflowInjectionPoint("query", "q"),
            "app.py:42", _policy(), transport=httpx.MockTransport(handler),
        )
    )
    assert result.injected is True
    assert result.reflected_in_response is True
    assert captured["token"] == result.token
    assert result.status == ValidationStatus.REVIEW_ONLY


def test_validate_dataflow_correlation_not_reflected_is_rejected() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="no trace of it here")

    result = asyncio.run(
        validate_dataflow_correlation(
            "https://ai.example.com/search", "xss_reflection", DataflowInjectionPoint("query", "q"),
            "app.py:42", _policy(), transport=httpx.MockTransport(handler),
        )
    )
    assert result.injected is True
    assert result.reflected_in_response is False
    assert result.status == ValidationStatus.REJECTED


def test_validate_dataflow_correlation_header_injection_reaches_request_headers() -> None:
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["value"] = request.headers.get("X-Trace")
        return httpx.Response(200)

    result = asyncio.run(
        validate_dataflow_correlation(
            "https://ai.example.com/api", "xss_reflection", DataflowInjectionPoint("header", "X-Trace"),
            "app.py:10", _policy(), transport=httpx.MockTransport(handler),
        )
    )
    assert captured["value"] == result.token


def test_validate_dataflow_correlation_cookie_injection_reaches_request_cookies() -> None:
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["cookie_header"] = request.headers.get("Cookie", "")
        return httpx.Response(200)

    result = asyncio.run(
        validate_dataflow_correlation(
            "https://ai.example.com/api", "xss_reflection", DataflowInjectionPoint("cookie", "trace_id"),
            "app.py:10", _policy(), transport=httpx.MockTransport(handler),
        )
    )
    assert result.token in captured["cookie_header"]


def test_validate_dataflow_correlation_network_error_is_review_only() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    result = asyncio.run(
        validate_dataflow_correlation(
            "https://ai.example.com/search", "xss_reflection", DataflowInjectionPoint("query", "q"),
            "app.py:42", _policy(), transport=httpx.MockTransport(handler),
        )
    )
    assert result.skipped_reason is not None
    assert result.status == ValidationStatus.REVIEW_ONLY


def test_static_source_ref_and_runtime_observation_stay_separate_fields() -> None:
    result = asyncio.run(
        validate_dataflow_correlation(
            "https://ai.example.com/search", "xss_reflection", DataflowInjectionPoint("query", "q"),
            "app.py:99", _policy(), transport=httpx.MockTransport(lambda r: httpx.Response(200, text="nothing")),
        )
    )
    assert result.static_source_ref == "app.py:99"
    assert result.token not in result.static_source_ref


def test_dataflow_correlation_evidence_to_dict_is_json_serializable() -> None:
    result = asyncio.run(
        validate_dataflow_correlation(
            "https://ai.example.com/search", "xss_reflection", DataflowInjectionPoint("query", "q"),
            "app.py:42", _policy(), transport=httpx.MockTransport(lambda r: httpx.Response(200, text="x")),
        )
    )
    json.dumps(result.to_dict())
