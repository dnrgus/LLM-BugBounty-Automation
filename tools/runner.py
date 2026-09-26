from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from core.cancel import CancellationToken
from core.tool_doctor import ToolStatus, check_tool, detect_version
from reporting.sanitizer import sanitize_text
from scope.policy import PolicyEngine


@dataclass(frozen=True)
class ExternalScanOptions:
    """WP-05/06: per-scan knobs threaded to external tool execution so a
    token is entered once and reused (§19), scans aren't cut off by a
    too-short default (§20), and nuclei can fuzz parameters (§7).

    Defaults reproduce the original behavior exactly (no auth, 120s, no
    DAST), so any caller that doesn't pass options is unchanged.
    """

    auth_headers: dict[str, str] = field(default_factory=dict)
    tool_timeout: float = 120.0
    nuclei_dast: bool = False
    full_templates: bool = False
    param_endpoints: tuple[str, ...] = ()


def _redact_argv(command: list[str]) -> list[str]:
    """Mask credentials in an argv before it is stored/printed. The real
    argv is only ever handed to the subprocess; everything persisted or
    returned (ToolExecutionResult.command -> scan JSON on stdout, evidence)
    goes through this so an auth header value never leaks."""
    return [sanitize_text(arg)[0] for arg in command]


@dataclass(frozen=True)
class ExternalTool:
    """P3.1-3 (roadmap v3.1.0 Operational Pipeline): one external
    binary's execution contract -- check_available/build_command/
    parse_output/normalize -- kept as plain data + pure functions so
    run_external_tool() never needs to know which specific tool it's
    running.

    build_command MUST return an argv list (never a shell string) whose
    first element is exactly `binary`. run_external_tool() always
    executes through asyncio.create_subprocess_exec (shell=False
    equivalent -- there is no shell to parse, so a target string can
    never inject a second command), but this contract is still checked
    defensively so a mis-defined ExternalTool fails loudly instead of
    silently running the wrong thing.
    """

    id: str
    binary: str
    build_command: Callable[[str], list[str]]
    parse_output: Callable[[str], list[dict[str, Any]]]
    normalizer: Any  # .parse(records, run_id, target_id, version=None) -> list[...]


@dataclass(frozen=True)
class ToolExecutionResult:
    tool_id: str
    status: str  # ran | skipped_tool_not_installed | skipped_out_of_scope | timeout | error
    detail: str
    command: list[str] = field(default_factory=list)
    version: str | None = None
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    findings: list[Any] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "tool_id": self.tool_id,
            "status": self.status,
            "detail": self.detail,
            "command": self.command,
            "version": self.version,
            "returncode": self.returncode,
            "duration_seconds": round(self.duration_seconds, 3),
            "finding_count": len(self.findings),
            "findings": [finding.to_dict() for finding in self.findings],
        }


async def run_external_tool(
    tool: ExternalTool,
    target: str,
    policy: PolicyEngine,
    run_id: str,
    target_id: str,
    timeout_seconds: float = 120.0,
    tool_checker: Callable[[str], ToolStatus] = check_tool,
    cancellation: CancellationToken | None = None,
) -> ToolExecutionResult:
    """P3.1-3: runs one real external tool binary against one target,
    gated by Policy/Scope before a single subprocess is spawned.

    Only network-shaped targets (http/https URLs) go through
    policy.validate_url -- a local filesystem path (e.g. trufflehog's
    filesystem scan mode) never makes an outbound request, so it isn't a
    Scope decision the same way a live URL target is.

    cancellation (P3.4-2, roadmap v3.4.0 Production Hardening): optional.
    When given, an explicit cancel() during the subprocess's run kills it
    immediately (status "cancelled"), the same way an internal timeout
    already did before this parameter existed -- omitting it keeps the
    exact original timeout-only behavior.
    """
    status = tool_checker(tool.binary)
    if not status.available:
        return ToolExecutionResult(
            tool_id=tool.id,
            status="skipped_tool_not_installed",
            detail=f"{tool.binary} is not installed on this machine",
        )

    if target.startswith(("http://", "https://")):
        decision = policy.validate_url(target)
        if not decision.allowed:
            return ToolExecutionResult(
                tool_id=tool.id,
                status="skipped_out_of_scope",
                detail=f"target blocked by scope/policy: {decision.reason}",
            )

    command = tool.build_command(target)
    if not command or command[0] != tool.binary:
        raise ValueError(f"{tool.id}: build_command()[0] must be {tool.binary!r}, got {command!r}")
    # Only the real `command` is handed to the subprocess; every result that
    # is stored, returned or printed uses the redacted copy (WP-05).
    safe_command = _redact_argv(command)

    started = time.monotonic()
    process = await asyncio.create_subprocess_exec(
        *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )

    if cancellation is None:
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
        except asyncio.TimeoutError:
            process.kill()
            # communicate(), not wait(): drains and closes the stdout/stderr
            # pipes too, so a killed tool never leaks its transports.
            await process.communicate()
            return ToolExecutionResult(
                tool_id=tool.id,
                status="timeout",
                command=safe_command,
                detail=f"{tool.binary} exceeded {timeout_seconds}s timeout and was killed",
                duration_seconds=time.monotonic() - started,
            )
    else:
        communicate_task = asyncio.ensure_future(process.communicate())
        cancel_wait_task = asyncio.ensure_future(cancellation.wait())
        done, pending = await asyncio.wait(
            {communicate_task, cancel_wait_task}, timeout=timeout_seconds, return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()

        if communicate_task not in done:
            process.kill()
            # communicate(), not wait(): drains and closes the stdout/stderr
            # pipes too, so a killed tool never leaks its transports.
            await process.communicate()
            if cancel_wait_task in done:
                return ToolExecutionResult(
                    tool_id=tool.id,
                    status="cancelled",
                    command=safe_command,
                    detail=f"{tool.binary} was cancelled: {cancellation.reason}",
                    duration_seconds=time.monotonic() - started,
                )
            return ToolExecutionResult(
                tool_id=tool.id,
                status="timeout",
                command=safe_command,
                detail=f"{tool.binary} exceeded {timeout_seconds}s timeout and was killed",
                duration_seconds=time.monotonic() - started,
            )
        stdout_bytes, stderr_bytes = communicate_task.result()
    duration = time.monotonic() - started
    stdout = stdout_bytes.decode("utf-8", errors="replace")
    stderr = stderr_bytes.decode("utf-8", errors="replace")

    if process.returncode != 0:
        return ToolExecutionResult(
            tool_id=tool.id,
            status="error",
            command=safe_command,
            detail=f"{tool.binary} exited {process.returncode}",
            returncode=process.returncode,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
        )

    version = status.version or detect_version(tool.binary)
    records = tool.parse_output(stdout)
    findings = tool.normalizer.parse(records, run_id=run_id, target_id=target_id, version=version)
    return ToolExecutionResult(
        tool_id=tool.id,
        status="ran",
        command=safe_command,
        detail=f"parsed {len(findings)} finding(s) from a live {tool.binary} run",
        version=version,
        returncode=0,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=duration,
        findings=findings,
    )
