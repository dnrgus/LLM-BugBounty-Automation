"""P4.5 WP-02 (v5.0 plan 5.2): tester-supplied auth contexts, object-id
candidates, and the read-only object access comparison."""

import asyncio
from pathlib import Path

import httpx
import pytest

from core.models import FindingStatus
from scope.policy import PolicyEngine
from source.endpoints import EndpointSpec
from validation.auth_contexts import AuthContextSet, TesterAccount, load_auth_contexts, object_id_candidates
from validation.auth_validator import AuthContext
from validation.finding_adapter import finding_from_object_access
from validation.object_access_validator import validate_object_access

SPEC = EndpointSpec(method="GET", path="/api/notes/<int:note_id>", path_params=["note_id"], file="app.py", line=1)


def _policy() -> PolicyEngine:
    return PolicyEngine(
        {"scope": {"domains": ["ai.example.com"], "url_patterns": ["https://ai.example.com/*"]}, "testing": {"automated_scanning": True}}
    )


def _account(ident: str, note_id: str | None = "101") -> TesterAccount:
    return TesterAccount(
        context=AuthContext(id=ident, principal_label=ident, credential_source="env", headers={"Authorization": f"Bearer tok-{ident}"}),
        owned_objects={"note_id": note_id} if note_id else {},
    )


def _transport(calls: list[httpx.Request], responder) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return responder(request)

    return httpx.MockTransport(handler)


def test_load_auth_contexts_resolves_env_and_never_serializes_credentials(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("USER_A_TOKEN", "secret-a")
    path = tmp_path / "auth.yaml"
    path.write_text(
        "accounts:\n"
        "  - id: user_a\n    headers: {Authorization: 'Bearer ${USER_A_TOKEN}'}\n    owned_objects: {note_id: '101'}\n"
        "  - id: user_b\n    headers: {Authorization: 'Bearer ${USER_B_TOKEN}'}\n",
        encoding="utf-8",
    )
    contexts = load_auth_contexts(path)
    user_a, user_b = contexts.accounts
    assert user_a.context.headers["Authorization"] == "Bearer secret-a"
    assert user_a.usable
    assert not user_b.usable and user_b.missing_env == ["USER_B_TOKEN"]
    assert "secret-a" not in str(contexts.to_dict())
    assert [account.context.id for account in contexts.usable_accounts()] == ["user_a"]


def test_load_auth_contexts_rejects_literal_credentials(tmp_path: Path) -> None:
    path = tmp_path / "auth.yaml"
    path.write_text("accounts:\n  - id: a\n    headers: {Authorization: 'Bearer literal'}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="environment variable"):
        load_auth_contexts(path)


def test_object_id_candidates_by_name() -> None:
    spec = EndpointSpec(method="GET", path="/x/{id}", path_params=["id"], query_params=["userId", "paid", "q"], body_fields=["order_id"])
    assert object_id_candidates(spec) == [
        {"location": "path", "name": "id"},
        {"location": "query", "name": "userId"},
        {"location": "body", "name": "order_id"},
    ]


def test_missing_second_account_is_needs_review_and_sends_nothing() -> None:
    calls: list[httpx.Request] = []
    result = asyncio.run(
        validate_object_access(SPEC, "https://ai.example.com", AuthContextSet([_account("a")]), _policy(),
                               transport=_transport(calls, lambda r: httpx.Response(200)))
    )
    assert calls == []
    assert result.verdict == "needs_review"
    assert "found 1" in result.reason


def test_state_changing_method_is_not_automated() -> None:
    calls: list[httpx.Request] = []
    spec = EndpointSpec(method="PUT", path=SPEC.path, path_params=["note_id"])
    result = asyncio.run(
        validate_object_access(spec, "https://ai.example.com", AuthContextSet([_account("a"), _account("b")]), _policy(),
                               transport=_transport(calls, lambda r: httpx.Response(200)))
    )
    assert calls == []
    assert result.verdict == "needs_review"


def test_out_of_scope_base_url_is_blocked_before_sending() -> None:
    calls: list[httpx.Request] = []
    result = asyncio.run(
        validate_object_access(SPEC, "https://evil.example.net", AuthContextSet([_account("a"), _account("b")]), _policy(),
                               transport=_transport(calls, lambda r: httpx.Response(200)))
    )
    assert calls == []
    assert "blocked by policy" in result.reason


def test_other_account_denied_is_rejected() -> None:
    calls: list[httpx.Request] = []

    def responder(request: httpx.Request) -> httpx.Response:
        if request.headers["Authorization"] == "Bearer tok-a":
            return httpx.Response(200, json={"id": 101, "owner": "a"})
        return httpx.Response(403, json={"error": "forbidden"})

    result = asyncio.run(
        validate_object_access(SPEC, "https://ai.example.com", AuthContextSet([_account("a"), _account("b", "202")]), _policy(),
                               key_fields=["owner"], transport=_transport(calls, responder))
    )
    assert [str(call.url) for call in calls] == ["https://ai.example.com/api/notes/101"] * 2
    assert result.verdict == "rejected"


def test_other_account_receiving_owner_fields_is_confirmed_with_hashed_evidence() -> None:
    calls: list[httpx.Request] = []
    result = asyncio.run(
        validate_object_access(SPEC, "https://ai.example.com", AuthContextSet([_account("a"), _account("b", "202")]), _policy(),
                               key_fields=["owner"],
                               transport=_transport(calls, lambda r: httpx.Response(200, json={"id": 101, "owner": "owner-a-private"})))
    )
    assert result.verdict == "confirmed"
    evidence = str(result.to_dict())
    assert "owner-a-private" not in evidence  # only hashes of key fields are kept
    assert "tok-a" not in evidence
    finding = finding_from_object_access("run_x", result, "ev_1")
    assert finding.status is FindingStatus.CONFIRMED


def test_same_shape_without_key_fields_stays_needs_review() -> None:
    calls: list[httpx.Request] = []
    result = asyncio.run(
        validate_object_access(SPEC, "https://ai.example.com", AuthContextSet([_account("a"), _account("b", "202")]), _policy(),
                               transport=_transport(calls, lambda r: httpx.Response(200, json={"id": 1})))
    )
    assert result.verdict == "needs_review"
    assert finding_from_object_access("run_x", result, "ev_1").status is FindingStatus.NEEDS_REVIEW
