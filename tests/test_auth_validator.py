"""P4.1-C Auth Validator (roadmap v4.1.0 Dynamic Validation Expansion)."""

import asyncio

import httpx

from core.models import FindingStatus
from scope.policy import PolicyEngine
from validation.auth_validator import ANONYMOUS_CONTEXT, AuthContext, compare_auth_contexts
from validation.contract import ValidationStatus


def _policy() -> PolicyEngine:
    return PolicyEngine(
        {
            "program": "auth-validator-test",
            "scope": {"domains": ["ai.example.com"], "url_patterns": ["https://ai.example.com/*"]},
            "testing": {"automated_scanning": True},
        }
    )


def _session_a() -> AuthContext:
    return AuthContext(
        id="session_a", principal_label="user A", session_ref="A", credential_source="fixture",
        headers={"Authorization": "Bearer fixture-token-a"},
    )


def test_auth_context_to_dict_never_includes_headers() -> None:
    context = _session_a()
    dumped = context.to_dict()
    assert "headers" not in dumped
    assert "Bearer" not in str(dumped)


def test_compare_auth_contexts_blocked_out_of_scope_returns_no_observations() -> None:
    result = asyncio.run(
        compare_auth_contexts(
            "https://evil.example.net/x", "GET", _session_a(), ANONYMOUS_CONTEXT, _policy(),
            transport=httpx.MockTransport(lambda r: httpx.Response(200)),
        )
    )
    assert result.observations == []
    assert result.status == ValidationStatus.REVIEW_ONLY


def test_compare_auth_contexts_confirms_when_probe_reaches_the_same_successful_shape() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "application/json"}, text='{"id": 1, "owner": "a"}')

    result = asyncio.run(
        compare_auth_contexts(
            "https://ai.example.com/api/resource/1", "GET", _session_a(), ANONYMOUS_CONTEXT, _policy(),
            transport=httpx.MockTransport(handler),
        )
    )
    assert result.status == ValidationStatus.CONFIRMED


def test_compare_auth_contexts_rejects_when_probe_is_denied() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("Authorization"):
            return httpx.Response(200, headers={"content-type": "application/json"}, text='{"id": 1}')
        return httpx.Response(403)

    result = asyncio.run(
        compare_auth_contexts(
            "https://ai.example.com/api/resource/1", "GET", _session_a(), ANONYMOUS_CONTEXT, _policy(),
            transport=httpx.MockTransport(handler),
        )
    )
    assert result.status == ValidationStatus.REJECTED


def test_compare_auth_contexts_review_only_when_success_shapes_differ() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("Authorization"):
            return httpx.Response(200, headers={"content-type": "application/json"}, text='{"id": 1, "owner": "a"}')
        return httpx.Response(200, headers={"content-type": "application/json"}, text='{"public": true}')

    result = asyncio.run(
        compare_auth_contexts(
            "https://ai.example.com/api/resource/1", "GET", _session_a(), ANONYMOUS_CONTEXT, _policy(),
            transport=httpx.MockTransport(handler),
        )
    )
    assert result.status == ValidationStatus.REVIEW_ONLY


def test_compare_auth_contexts_unstable_when_probe_succeeds_but_control_does_not() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("Authorization"):
            return httpx.Response(500)  # control itself is broken -- surprising, needs review
        return httpx.Response(200, headers={"content-type": "application/json"}, text="{}")

    result = asyncio.run(
        compare_auth_contexts(
            "https://ai.example.com/api/resource/1", "GET", _session_a(), ANONYMOUS_CONTEXT, _policy(),
            transport=httpx.MockTransport(handler),
        )
    )
    assert result.status == ValidationStatus.UNSTABLE


def test_compare_auth_contexts_unstable_on_network_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    result = asyncio.run(
        compare_auth_contexts(
            "https://ai.example.com/api/resource/1", "GET", _session_a(), ANONYMOUS_CONTEXT, _policy(),
            transport=httpx.MockTransport(handler),
        )
    )
    assert result.status == ValidationStatus.UNSTABLE


def test_each_context_receives_only_its_own_headers() -> None:
    seen_auth_headers = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_auth_headers.append(request.headers.get("Authorization"))
        return httpx.Response(200)

    asyncio.run(
        compare_auth_contexts(
            "https://ai.example.com/api/resource/1", "GET", _session_a(), ANONYMOUS_CONTEXT, _policy(),
            transport=httpx.MockTransport(handler),
        )
    )
    assert seen_auth_headers == ["Bearer fixture-token-a", None]


def test_selected_fields_extracts_only_requested_json_keys() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "application/json"}, text='{"id": 1, "secret": "s", "owner": "a"}')

    result = asyncio.run(
        compare_auth_contexts(
            "https://ai.example.com/api/resource/1", "GET", _session_a(), ANONYMOUS_CONTEXT, _policy(),
            selected_fields=["id", "owner"], transport=httpx.MockTransport(handler),
        )
    )
    for observation in result.observations:
        assert observation.selected_fields == {"id": 1, "owner": "a"}
        assert "secret" not in observation.selected_fields


def test_body_shape_is_key_order_independent() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("Authorization"):
            return httpx.Response(200, headers={"content-type": "application/json"}, text='{"a": 1, "b": 2}')
        return httpx.Response(200, headers={"content-type": "application/json"}, text='{"b": 2, "a": 1}')

    result = asyncio.run(
        compare_auth_contexts(
            "https://ai.example.com/api/resource/1", "GET", _session_a(), ANONYMOUS_CONTEXT, _policy(),
            transport=httpx.MockTransport(handler),
        )
    )
    control, probe = result.observations
    assert control.body_shape == probe.body_shape
    assert result.status == ValidationStatus.CONFIRMED


def test_auth_comparison_to_dict_is_json_serializable() -> None:
    import json

    result = asyncio.run(
        compare_auth_contexts(
            "https://ai.example.com/api/resource/1", "GET", _session_a(), ANONYMOUS_CONTEXT, _policy(),
            transport=httpx.MockTransport(lambda r: httpx.Response(200)),
        )
    )
    json.dumps(result.to_dict())


def test_confirmed_status_matches_findingstatus_vocabulary() -> None:
    # ValidationStatus.CONFIRMED/REJECTED/UNSTABLE intentionally share
    # their string value with core.models.FindingStatus -- proving the
    # P4.1-A contract's vocabulary is genuinely compatible, not just
    # similarly named.
    assert ValidationStatus.CONFIRMED.value == FindingStatus.CONFIRMED.value
    assert ValidationStatus.REJECTED.value == FindingStatus.REJECTED.value
    assert ValidationStatus.UNSTABLE.value == FindingStatus.UNSTABLE.value
