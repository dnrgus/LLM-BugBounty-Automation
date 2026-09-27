"""WP-04: safe auto-scope generation and its CLI wiring."""

import json

import pytest

from cli import main
from scope.auto import ScopeNotAutoAllowedError, build_auto_scope, is_auto_allowed_host
from scope.policy import PolicyEngine


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "192.168.1.10", "10.0.0.5", "172.16.3.4", "::1"])
def test_local_and_private_hosts_are_auto_allowed(host: str) -> None:
    assert is_auto_allowed_host(host) is True


@pytest.mark.parametrize("host", ["example.com", "8.8.8.8", "1.1.1.1", "api.target.io", ""])
def test_public_hosts_are_not_auto_allowed(host: str) -> None:
    assert is_auto_allowed_host(host) is False


def test_build_auto_scope_puts_local_target_in_scope() -> None:
    engine = PolicyEngine(build_auto_scope("http://127.0.0.1:3000"))
    assert engine.validate_url("http://127.0.0.1:3000").allowed is True
    assert engine.validate_url("http://127.0.0.1:3000/rest/products/search?q=1").allowed is True


def test_build_auto_scope_keeps_safety_defaults_conservative() -> None:
    scope = build_auto_scope("http://localhost:8080")
    assert scope["testing"]["destructive_actions"] is False
    assert scope["testing"]["denial_of_service"] is False
    assert scope["testing"]["state_changing_requests"] == "dry_run"
    assert "delete" in scope["blocked_actions"]


def test_build_auto_scope_rejects_public_host() -> None:
    with pytest.raises(ScopeNotAutoAllowedError):
        build_auto_scope("https://example.com")


def test_scan_public_url_without_scope_exits_3(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["scan", "https://example.com"])
    assert rc == 3
    err = json.loads(capsys.readouterr().err)
    assert err["error"] == "ScopeNotAutoAllowedError"
