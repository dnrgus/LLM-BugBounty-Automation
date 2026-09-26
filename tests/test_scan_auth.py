"""WP-05: auth context reuse across scanners, timeout config, and credential
redaction in stored/printed commands."""

import argparse

import pytest

from cli import _auth_from_args, _scan_options_from_args
from tools.dalfox import make_dalfox_tool
from tools.nuclei import make_nuclei_tool
from tools.runner import ExternalScanOptions, _redact_argv


def _args(**kw: object) -> argparse.Namespace:
    base = {"header": None, "auth_token": None, "tool_timeout": 600.0, "nuclei_dast": False, "full_templates": False}
    base.update(kw)
    return argparse.Namespace(**base)


def test_nuclei_command_includes_auth_header() -> None:
    tool = make_nuclei_tool(ExternalScanOptions(auth_headers={"Authorization": "Bearer T"}))
    command = tool.build_command("http://127.0.0.1:3000")
    assert "-H" in command
    assert "Authorization: Bearer T" in command


def test_dalfox_command_includes_auth_header() -> None:
    tool = make_dalfox_tool(ExternalScanOptions(auth_headers={"Authorization": "Bearer T"}))
    command = tool.build_command("http://127.0.0.1:3000")
    assert "--header" in command
    assert "Authorization: Bearer T" in command


def test_redact_argv_masks_bearer_token() -> None:
    redacted = _redact_argv(["nuclei", "-H", "Authorization: Bearer SUPERSECRET", "-u", "http://x"])
    joined = " ".join(redacted)
    assert "SUPERSECRET" not in joined
    assert "[REDACTED]" in joined


def test_auth_from_args_parses_header_and_token() -> None:
    auth = _auth_from_args(_args(auth_token="tok", header=["X-Api-Key: k", "X-Trace: 1"]))
    headers = auth.as_request_headers()
    assert headers["Authorization"] == "Bearer tok"
    assert headers["X-Api-Key"] == "k"
    assert headers["X-Trace"] == "1"


def test_auth_from_args_rejects_malformed_header() -> None:
    with pytest.raises(ValueError):
        _auth_from_args(_args(header=["not-a-header"]))


def test_auth_from_args_falls_back_to_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BUGBOUNTY_AUTH_TOKEN", "env-token")
    auth = _auth_from_args(_args())
    assert auth.token == "env-token"


def test_scan_options_from_args_threads_timeout_and_dast() -> None:
    opts = _scan_options_from_args(_args(tool_timeout=42.0, nuclei_dast=True, full_templates=True))
    assert opts.tool_timeout == 42.0
    assert opts.nuclei_dast is True
    assert opts.full_templates is True


def test_default_options_reproduce_original_command() -> None:
    tool = make_nuclei_tool()
    assert tool.build_command("http://x") == ["nuclei", "-u", "http://x", "-jsonl", "-silent"]
