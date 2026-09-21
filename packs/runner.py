from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from adapters.scanner.dalfox import DalfoxAdapter
from adapters.scanner.nuclei import NucleiAdapter
from adapters.secrets.trufflehog import TruffleHogAdapter
from core.models import new_id
from core.orchestrator import run_sample_pipeline
from core.profile import PipelineProfile
from core.tool_doctor import ToolStatus, check_tool
from packs.selector import PackSelection
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from testcase.schema import Testcase

_EXTERNAL_TOOL_ADAPTERS = {
    "nuclei": NucleiAdapter,
    "dalfox": DalfoxAdapter,
    "trufflehog": TruffleHogAdapter,
}


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
      secret_scan/trufflehog) are never invoked directly -- this
      project has never shelled out to live pentesting binaries
      against a real target (see core/orchestrator.py's
      _normalize_external_scan), and U7 does not change that. A pack
      is "ran" only when its results file is supplied by the caller;
      otherwise the reason is reported explicitly (tool not installed,
      or installed but no results file yet) rather than silently
      skipped.

    Only *selected* packs (selection.selected is True) are considered --
    U6's reasons for skipping the rest are already recorded on the
    PackSelection itself.
    """
    external_scan_inputs = external_scan_inputs or {}
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
            results.append(_run_external_tool_pack(pack.id, tool_id, external_scan_inputs, tool_checker))

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


def _run_external_tool_pack(
    pack_id: str,
    tool_id: str,
    external_scan_inputs: dict[str, Path | str],
    tool_checker: Callable[[str], ToolStatus],
) -> PackRunResult:
    path = external_scan_inputs.get(tool_id)
    if path is None:
        status = tool_checker(tool_id)
        if status.available:
            detail = (
                f"{tool_id} is installed ({status.path}) but no results file was supplied -- "
                f"run {tool_id} against the discovered in-scope endpoints and pass its output"
            )
            return PackRunResult(pack_id=pack_id, tool_id=tool_id, status="skipped_no_results_file", detail=detail)
        return PackRunResult(
            pack_id=pack_id,
            tool_id=tool_id,
            status="skipped_tool_not_installed",
            detail=f"{tool_id} is not installed on this machine",
        )

    adapter_cls = _EXTERNAL_TOOL_ADAPTERS[tool_id]
    findings = adapter_cls().parse_file(path, run_id=new_id("run"), target_id="pack_run")
    return PackRunResult(
        pack_id=pack_id,
        tool_id=tool_id,
        status="ran",
        detail=f"parsed {len(findings)} finding(s) from {tool_id} output",
        summary={"count": len(findings), "findings": [finding.to_dict() for finding in findings]},
    )
