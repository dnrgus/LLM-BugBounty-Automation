from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from tools.adapters.scanner.dalfox import DalfoxAdapter
from tools.adapters.scanner.nuclei import NucleiAdapter
from tools.adapters.secrets.trufflehog import TruffleHogAdapter
from core.models import new_id
from core.orchestrator import run_sample_pipeline
from core.profile import PipelineProfile
from core.tool_doctor import ToolStatus, check_tool
from packs.selector import PackSelection
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from testcase.schema import Testcase
from tools.dalfox import make_dalfox_tool
from tools.nuclei import make_nuclei_tool
from tools.runner import ExternalScanOptions, run_external_tool

_EXTERNAL_TOOL_ADAPTERS = {
    "nuclei": NucleiAdapter,
    "dalfox": DalfoxAdapter,
    "trufflehog": TruffleHogAdapter,
}

# P3.1-3: tools with a real ExternalTool execution contract (tools/runner.py).
# trufflehog is deliberately absent -- it only has a filesystem-scan mode
# here (see tools/trufflehog.py), which doesn't fit "run against this live
# URL" the way nuclei/dalfox do. Built per-run from ExternalScanOptions so
# auth headers / DAST flags apply (WP-05/06).
_LIVE_TOOL_FACTORIES = {"nuclei": make_nuclei_tool, "dalfox": make_dalfox_tool}


@dataclass
class PackRunResult:
    pack_id: str
    tool_id: str
    status: str  # "ran" | "skipped_tool_not_installed" | "skipped_no_results_file" | "skipped_no_target"
    detail: str
    summary: dict[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "pack_id": self.pack_id,
            "tool_id": self.tool_id,
            "status": self.status,
            "detail": self.detail,
            "summary": self.summary,
        }


async def run_selected_packs(
    selections: list[PackSelection],
    testcases: list[Testcase],
    policy: PolicyEngine,
    store: SQLiteStore,
    target_kind: str | None = None,
    target_config: Path | str | None = None,
    profile: PipelineProfile | None = None,
    external_scan_inputs: dict[str, Path | str] | None = None,
    tool_checker: Callable[[str], ToolStatus] = check_tool,
    live_target_url: str | None = None,
    options: ExternalScanOptions | None = None,
) -> list[PackRunResult]:
    """U7 (design doc section 9): connects each *selected* Attack Pack
    (U6) to a real execution path -- "외부 툴 + 자체 verifier를 pack으로
    연결".

    - testcase_suite packs (llm_core / rag_injection / agent_tool_abuse)
      share one run: their testing_categories are unioned, the existing
      testcase suite is filtered down to just those categories, and the
      whole thing runs through the existing scan pipeline
      (run_sample_pipeline: Executor -> JudgeEnsemble -> Reproducer,
      i.e. the "자체 verifier" this project already has) exactly as a
      normal scan would.
    - External-tool packs (web_scan/nuclei, api_fuzz/dalfox,
      secret_scan/trufflehog): if a results file is supplied, that's
      always used (a program's own recon workflow producing a results
      file stays authoritative). Otherwise, as of P3.1-3 (roadmap
      v3.1.0), nuclei/dalfox actually run live against `live_target_url`
      when installed and a Policy/Scope check on that URL passes (see
      tools/runner.py) -- no longer parser-only for those two. trufflehog
      still has no live-URL mode here (see tools/trufflehog.py) and stays
      results-file-only. Every other case (tool not installed, no results
      file and no live_target_url) is reported explicitly rather than
      silently skipped.

    Only *selected* packs (selection.selected is True) are considered --
    U6's reasons for skipping the rest are already recorded on the
    PackSelection itself.
    """
    external_scan_inputs = external_scan_inputs or {}
    options = options or ExternalScanOptions()
    results: list[PackRunResult] = []
    testcase_suite_categories: set[str] = set()

    for selection in selections:
        if not selection.selected:
            continue
        pack = selection.pack
        for tool_id in pack.tool_ids:
            if tool_id == "testcase_suite":
                testcase_suite_categories.update(pack.testing_categories)
                continue
            results.append(
                await _run_external_tool_pack(
                    pack.id, tool_id, external_scan_inputs, tool_checker, policy, live_target_url, options
                )
            )

    if testcase_suite_categories:
        results.append(
            await _run_testcase_suite_packs(
                testcase_suite_categories, testcases, policy, store, target_kind, target_config, profile
            )
        )

    return results


async def _run_testcase_suite_packs(
    categories: set[str],
    testcases: list[Testcase],
    policy: PolicyEngine,
    store: SQLiteStore,
    target_kind: str | None,
    target_config: Path | str | None,
    profile: PipelineProfile | None,
) -> PackRunResult:
    if target_kind is None:
        return PackRunResult(
            pack_id="testcase_suite_packs",
            tool_id="testcase_suite",
            status="skipped_no_target",
            detail="no target_kind/target_config supplied to run testcase-suite packs against",
        )

    filtered = [case for case in testcases if case.category in categories]
    pipeline_result = await run_sample_pipeline(
        policy, filtered, store, target_kind=target_kind, profile=profile, target_config=target_config
    )
    return PackRunResult(
        pack_id="testcase_suite_packs",
        tool_id="testcase_suite",
        status="ran",
        detail=f"ran {len(filtered)} testcase(s) across categories {sorted(categories)}",
        summary=pipeline_result,
    )


async def _run_external_tool_pack(
    pack_id: str,
    tool_id: str,
    external_scan_inputs: dict[str, Path | str],
    tool_checker: Callable[[str], ToolStatus],
    policy: PolicyEngine,
    live_target_url: str | None,
    options: ExternalScanOptions | None = None,
) -> PackRunResult:
    options = options or ExternalScanOptions()
    path = external_scan_inputs.get(tool_id)
    if path is not None:
        adapter_cls = _EXTERNAL_TOOL_ADAPTERS[tool_id]
        findings = adapter_cls().parse_file(path, run_id=new_id("run"), target_id="pack_run")
        return PackRunResult(
            pack_id=pack_id,
            tool_id=tool_id,
            status="ran",
            detail=f"parsed {len(findings)} finding(s) from {tool_id} output",
            summary={"count": len(findings), "findings": [finding.to_dict() for finding in findings]},
        )

    status = tool_checker(tool_id)
    if not status.available:
        return PackRunResult(
            pack_id=pack_id,
            tool_id=tool_id,
            status="skipped_tool_not_installed",
            detail=f"{tool_id} is not installed on this machine",
        )

    factory = _LIVE_TOOL_FACTORIES.get(tool_id)
    if factory is not None and live_target_url is not None:
        # WP-06: nuclei DAST against the parameterized endpoints reused from
        # discovery. The endpoints go in a temp -l list; live_target_url is
        # still what run_external_tool validates against Policy/Scope, and
        # every listed URL was already scope-validated by collect_param_endpoints.
        list_path: str | None = None
        if tool_id == "nuclei" and options.nuclei_dast and options.param_endpoints:
            fd, list_path = tempfile.mkstemp(prefix="nuclei_dast_", suffix=".txt")
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write("\n".join(options.param_endpoints) + "\n")
        try:
            # Only the DAST-with-endpoint-list case needs the dedicated
            # list-mode nuclei tool; every other case goes through the
            # factory dict (so tests can inject a fixture tool there).
            tool = make_nuclei_tool(options, target_list=list_path) if list_path is not None else factory(options)
            execution = await run_external_tool(
                tool,
                live_target_url,
                policy,
                run_id=new_id("run"),
                target_id="pack_run_live",
                timeout_seconds=options.tool_timeout,
            )
        finally:
            if list_path is not None:
                os.unlink(list_path)
        summary = {"execution": execution.to_dict()}
        if execution.status == "ran":
            summary["count"] = len(execution.findings)
            summary["findings"] = [finding.to_dict() for finding in execution.findings]
        return PackRunResult(pack_id=pack_id, tool_id=tool_id, status=execution.status, detail=execution.detail, summary=summary)

    detail = (
        f"{tool_id} is installed ({status.path}) but no results file was supplied -- "
        f"run {tool_id} against the discovered in-scope endpoints and pass its output"
    )
    return PackRunResult(pack_id=pack_id, tool_id=tool_id, status="skipped_no_results_file", detail=detail)
