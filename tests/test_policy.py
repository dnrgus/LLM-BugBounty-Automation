from pathlib import Path

from scope.policy import PolicyEngine


def test_scope_allows_configured_url() -> None:
    engine = PolicyEngine.from_yaml(Path("config/scope.example.yaml"))
    decision = engine.validate_url("https://ai.example.com/api/chat")
    assert decision.allowed


def test_scope_blocks_other_domain() -> None:
    engine = PolicyEngine.from_yaml(Path("config/scope.example.yaml"))
    decision = engine.validate_url("https://evil.example.net/api/chat")
    assert not decision.allowed
    assert "out of scope" in decision.reason


def test_scope_blocks_denied_url_pattern() -> None:
    engine = PolicyEngine.from_yaml(Path("config/scope.example.yaml"))
    decision = engine.validate_url("https://ai.example.com/api/admin/users")
    assert not decision.allowed
    assert "explicitly denied" in decision.reason


def test_subdomain_requires_explicit_policy() -> None:
    engine = PolicyEngine.from_yaml(Path("config/scope.example.yaml"))
    decision = engine.validate_url("https://chat.ai.example.com/api/chat")
    assert not decision.allowed
    assert decision.metadata["hostname"] == "chat.ai.example.com"


def test_redirect_is_revalidated_and_record_only_when_out_of_scope() -> None:
    engine = PolicyEngine.from_yaml(Path("config/scope.example.yaml"))
    decision = engine.validate_redirect(
        "https://ai.example.com/api/chat",
        "https://evil.example.net/callback",
    )
    assert not decision.allowed
    assert decision.mode == "record-only"


def test_denied_testcase_category_is_blocked() -> None:
    engine = PolicyEngine.from_yaml(Path("config/scope.example.yaml"))
    decision = engine.validate_testcase("tool_abuse")
    assert not decision.allowed
    assert decision.reason == "test category denied"


def test_blocked_action_is_not_allowed() -> None:
    engine = PolicyEngine.from_yaml(Path("config/scope.example.yaml"))
    decision = engine.decide_action("delete")
    assert not decision.allowed
    assert decision.mode == "block"


def test_approval_required_action_is_simulated() -> None:
    engine = PolicyEngine.from_yaml(Path("config/scope.example.yaml"))
    decision = engine.decide_action("file_write")
    assert not decision.allowed
    assert decision.mode == "simulate"


def test_request_budget_is_enforced() -> None:
    engine = PolicyEngine({"limits": {"max_requests_per_run": 1}})
    first = engine.consume_request_budget()
    second = engine.consume_request_budget()
    assert first.allowed
    assert not second.allowed
    assert second.reason == "request budget exhausted"
    assert engine.budget_state.requests_remaining == 0


def test_policy_snapshot_contains_hash() -> None:
    engine = PolicyEngine.from_yaml(Path("config/scope.example.yaml"))
    snapshot = engine.snapshot
    assert snapshot["policy_hash"] == engine.policy_hash
    assert snapshot["program"] == "example-bugbounty"
