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


def test_blocked_action_is_not_allowed() -> None:
    engine = PolicyEngine.from_yaml(Path("config/scope.example.yaml"))
    decision = engine.decide_action("delete")
    assert not decision.allowed
    assert decision.mode == "block"

