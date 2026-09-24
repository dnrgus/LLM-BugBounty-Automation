"""P4.5 WP-01 (v5.0 plan 5.1): method risk + the state-changing request
gate, and the spec-driven endpoint validator honoring it."""

import asyncio

import httpx

from scope.policy import PolicyEngine, method_risk
from validation.contract import ValidationStatus
from validation.endpoint_validator import validate_endpoint_request


def _policy(**testing: object) -> PolicyEngine:
    return PolicyEngine(
        {
            "program": "method-policy-test",
            "scope": {"domains": ["ai.example.com"], "url_patterns": ["https://ai.example.com/*"]},
            "testing": {"automated_scanning": True, **testing},
        }
    )


def _recording_transport(calls: list[httpx.Request], status: int = 200) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(status, json={"ok": True})

    return httpx.MockTransport(handler)


def test_method_risk_levels() -> None:
    assert method_risk("get") == "read_only"
    assert method_risk("OPTIONS") == "read_only"
    assert method_risk("POST") == "state_changing"
    assert method_risk("PATCH") == "state_changing"
    assert method_risk("DELETE") == "destructive"
    assert method_risk("PROPFIND") == "state_changing"  # unknown verbs are never assumed safe


def test_state_changing_defaults_to_dry_run() -> None:
    decision = _policy().decide_method("POST")
    assert not decision.allowed
    assert decision.mode == "dry_run"


def test_state_changing_review_required_and_allowed_modes() -> None:
    assert _policy(state_changing_requests="review_required").decide_method("PUT").mode == "review_required"
    assert _policy(state_changing_requests="allowed").decide_method("PUT").allowed


def test_unknown_state_changing_setting_falls_back_to_dry_run() -> None:
    assert _policy(state_changing_requests="yolo").decide_method("POST").mode == "dry_run"


def test_delete_needs_destructive_actions_even_when_state_changing_is_allowed() -> None:
    assert _policy(state_changing_requests="allowed").decide_method("DELETE").mode == "review_required"
    assert _policy(state_changing_requests="allowed", destructive_actions=True).decide_method("DELETE").allowed


def test_delete_in_blocked_actions_blocks_outright() -> None:
    policy = PolicyEngine(
        {
            "scope": {"domains": ["ai.example.com"]},
            "testing": {"automated_scanning": True, "state_changing_requests": "allowed", "destructive_actions": True},
            "blocked_actions": ["delete"],
        }
    )
    decision = policy.decide_method("DELETE")
    assert not decision.allowed
    assert decision.mode == "block"


def test_validate_request_checks_scope_before_method() -> None:
    decision = _policy(state_changing_requests="allowed").validate_request("https://evil.example.net/x", "POST")
    assert not decision.allowed
    assert decision.reason == "domain out of scope"


def test_dry_run_request_is_planned_but_never_sent() -> None:
    calls: list[httpx.Request] = []
    evidence = asyncio.run(
        validate_endpoint_request(
            "https://ai.example.com/api/notes", "POST", _policy(),
            body_format="json", body_fields=["title"], example_body={"title": "UNIQUE-BODY-VALUE"},
            transport=_recording_transport(calls),
        )
    )
    assert calls == []
    assert evidence.execution_mode == "dry_run"
    assert evidence.status is ValidationStatus.REVIEW_ONLY
    assert evidence.planned_request is not None
    assert evidence.planned_request.body_fields == ["title"]
    assert "UNIQUE-BODY-VALUE" not in str(evidence.to_dict())  # field names only, never values


def test_allowed_state_changing_request_without_example_body_is_not_synthesized() -> None:
    calls: list[httpx.Request] = []
    evidence = asyncio.run(
        validate_endpoint_request(
            "https://ai.example.com/api/notes", "POST", _policy(state_changing_requests="allowed"),
            body_format="json", body_fields=["title"], transport=_recording_transport(calls),
        )
    )
    assert calls == []
    assert evidence.execution_mode == "review_required"


def test_allowed_state_changing_request_sends_example_body_once() -> None:
    calls: list[httpx.Request] = []
    evidence = asyncio.run(
        validate_endpoint_request(
            "https://ai.example.com/api/notes", "POST", _policy(state_changing_requests="allowed"),
            body_format="json", example_body={"title": "harmless"}, transport=_recording_transport(calls, 201),
        )
    )
    assert len(calls) == 1
    assert calls[0].method == "POST"
    assert b'"harmless"' in calls[0].read()
    assert evidence.status is ValidationStatus.CONFIRMED
    assert evidence.observation is not None and evidence.observation.status_code == 201


def test_read_only_request_executes_under_default_policy() -> None:
    calls: list[httpx.Request] = []
    evidence = asyncio.run(
        validate_endpoint_request("https://ai.example.com/api/search", "GET", _policy(), transport=_recording_transport(calls))
    )
    assert [call.method for call in calls] == ["GET"]
    assert evidence.execution_mode == "execute"


def test_out_of_scope_request_is_blocked_before_method_gate() -> None:
    calls: list[httpx.Request] = []
    evidence = asyncio.run(
        validate_endpoint_request(
            "https://evil.example.net/api", "POST", _policy(state_changing_requests="allowed"),
            example_body={}, transport=_recording_transport(calls),
        )
    )
    assert calls == []
    assert evidence.status is ValidationStatus.BLOCKED
