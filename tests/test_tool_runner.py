"""P3.1-3 External ToolRunner (roadmap v3.1.0 Operational Pipeline).

Exercises tools/runner.run_external_tool()'s check_available -> Policy/
Scope -> execute (shell=False) -> parse/normalize contract using small
local fixture "tool" scripts, so no real nuclei/dalfox/trufflehog binary
is required to run these tests.
"""

import asyncio
from pathlib import Path

import pytest

from tools.adapters.scanner.nuclei import NucleiAdapter
from core.tool_doctor import ToolStatus
from scope.policy import PolicyEngine
from tools.dalfox import _build_command as dalfox_build_command
from tools.nuclei import _build_command as nuclei_build_command
from tools.runner import ExternalTool, run_external_tool

_FIXTURE_JSONL = (
    '{"template-id": "fixture-template", "info": {"name": "Fixture Finding", '
    '"severity": "high", "tags": ["fixture"]}, "matched-at": "https://ai.example.com/api/"}'
)


def _policy() -> PolicyEngine:
    return PolicyEngine.from_yaml("config/scope.example.yaml")


def _write_fixture_binary(
    tmp_path: Path, name: str = "fixture-tool", marker: Path | None = None, sleep_seconds: float = 0, jsonl: str = ""
) -> Path:
    script = tmp_path / name
    # The --version check must come first and exit immediately: check_tool()
    # itself shells out with --version to detect the version, and that probe
    # must not count as "the tool actually ran against the target".
    lines = ["#!/bin/sh", 'if [ "$1" = "--version" ]; then echo "fixture-tool 1.2.3"; exit 0; fi']
    if marker is not None:
        lines.append(f"touch {marker}")
    if sleep_seconds:
        lines.append(f"sleep {sleep_seconds}")
    for line in jsonl.splitlines():
        if line.strip():
            lines.append(f"echo '{line}'")
    lines.append("exit 0")
    script.write_text("\n".join(lines) + "\n", encoding="utf-8")
    script.chmod(0o755)
    return script


def _fixture_tool(binary: Path, normalizer=None) -> ExternalTool:
    binary_str = str(binary)
    return ExternalTool(
        id="fixture",
        binary=binary_str,
        build_command=lambda target: [binary_str, "-u", target],
        parse_output=lambda stdout: [__import__("json").loads(line) for line in stdout.splitlines() if line.strip()],
        normalizer=normalizer or NucleiAdapter(),
    )


def test_nuclei_build_command_is_an_argv_list_with_the_target_as_one_element() -> None:
    command = nuclei_build_command("https://ai.example.com/api/")
    assert isinstance(command, list)
    assert command[0] == "nuclei"
    assert "https://ai.example.com/api/" in command


def test_dalfox_build_command_is_an_argv_list_with_the_target_as_one_element() -> None:
    command = dalfox_build_command("https://ai.example.com/api/")
    assert isinstance(command, list)
    assert command[0] == "dalfox"
    assert "https://ai.example.com/api/" in command


def test_run_external_tool_skips_when_binary_is_missing(tmp_path: Path) -> None:
    tool = _fixture_tool(tmp_path / "does-not-exist")
    result = asyncio.run(
        run_external_tool(tool, "https://ai.example.com/api/", _policy(), run_id="run_1", target_id="t")
    )
    assert result.status == "skipped_tool_not_installed"


def test_run_external_tool_rejects_out_of_scope_targets_without_ever_running_the_binary(tmp_path: Path) -> None:
    marker = tmp_path / "ran.marker"
    binary = _write_fixture_binary(tmp_path, marker=marker, jsonl=_FIXTURE_JSONL)
    tool = _fixture_tool(binary)

    result = asyncio.run(
        run_external_tool(tool, "https://evil.example.net/x", _policy(), run_id="run_1", target_id="t")
    )

    assert result.status == "skipped_out_of_scope"
    assert not marker.exists()


def test_run_external_tool_executes_a_local_fixture_binary_and_normalizes_its_output(tmp_path: Path) -> None:
    binary = _write_fixture_binary(tmp_path, jsonl=_FIXTURE_JSONL)
    tool = _fixture_tool(binary)

    result = asyncio.run(
        run_external_tool(tool, "https://ai.example.com/api/", _policy(), run_id="run_1", target_id="t")
    )

    assert result.status == "ran"
    assert result.command[0] == str(binary)
    assert result.version == "fixture-tool 1.2.3"
    assert len(result.findings) == 1
    assert result.findings[0].title == "Fixture Finding"
    payload = result.to_dict()
    import json

    json.dumps(payload)


def test_run_external_tool_kills_the_process_and_reports_timeout(tmp_path: Path) -> None:
    binary = _write_fixture_binary(tmp_path, sleep_seconds=5, jsonl=_FIXTURE_JSONL)
    tool = _fixture_tool(binary)

    result = asyncio.run(
        run_external_tool(
            tool, "https://ai.example.com/api/", _policy(), run_id="run_1", target_id="t", timeout_seconds=0.3
        )
    )

    assert result.status == "timeout"


def test_run_external_tool_reports_error_status_on_nonzero_exit(tmp_path: Path) -> None:
    script = tmp_path / "failing-tool"
    script.write_text("#!/bin/sh\nexit 7\n", encoding="utf-8")
    script.chmod(0o755)
    tool = _fixture_tool(script)

    result = asyncio.run(
        run_external_tool(tool, "https://ai.example.com/api/", _policy(), run_id="run_1", target_id="t")
    )

    assert result.status == "error"
    assert result.returncode == 7


def test_run_external_tool_rejects_a_build_command_that_does_not_start_with_the_binary(tmp_path: Path) -> None:
    binary = _write_fixture_binary(tmp_path, jsonl=_FIXTURE_JSONL)
    bad_tool = ExternalTool(
        id="bad", binary=str(binary), build_command=lambda target: ["sh", "-c", "echo pwned"],
        parse_output=lambda stdout: [], normalizer=NucleiAdapter(),
    )
    with pytest.raises(ValueError, match="build_command"):
        asyncio.run(run_external_tool(bad_tool, "https://ai.example.com/api/", _policy(), run_id="run_1", target_id="t"))


def test_run_external_tool_skips_scope_check_for_local_filesystem_targets(tmp_path: Path) -> None:
    # A filesystem path (e.g. trufflehog's scan mode) is never an outbound
    # request, so it isn't gated by policy.validate_url the way a URL is.
    binary = _write_fixture_binary(tmp_path, jsonl=_FIXTURE_JSONL)
    tool = _fixture_tool(binary)
    result = asyncio.run(
        run_external_tool(tool, str(tmp_path / "some" / "local" / "path"), _policy(), run_id="run_1", target_id="t")
    )
    assert result.status == "ran"


def test_run_external_tool_uses_the_caller_supplied_tool_checker(tmp_path: Path) -> None:
    binary = _write_fixture_binary(tmp_path, jsonl=_FIXTURE_JSONL)
    tool = _fixture_tool(binary)

    def always_unavailable(name: str) -> ToolStatus:
        return ToolStatus(name=name, available=False, path=None, version=None, status="warn")

    result = asyncio.run(
        run_external_tool(
            tool, "https://ai.example.com/api/", _policy(), run_id="run_1", target_id="t",
            tool_checker=always_unavailable,
        )
    )
    assert result.status == "skipped_tool_not_installed"
