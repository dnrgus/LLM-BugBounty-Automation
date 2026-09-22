from __future__ import annotations

from pathlib import Path

from core.models import Finding, FindingStatus, new_id
from packs.runner import PackRunResult
from reporting.evidence import write_evidence_bundle
from storage.sqlite import SQLiteStore


def promote_external_tool_findings(
    pack_runs: list[PackRunResult], run_id: str, store: SQLiteStore
) -> list[Finding]:
    """P3.1-4 (roadmap v3.1.0 Operational Pipeline): promotes each
    external tool's normalized result (nuclei/dalfox/trufflehog, whether
    parsed from a results file or -- since P3.1-3 -- executed live) into
    a first-class Finding, the same way scenario/finding.py does for
    flagged Scenario steps. Without this, a Pack's tool findings stayed
    opaque JSON inside PackRunResult.summary, never entering the
    Finding/Evidence/Report lifecycle or getting a
    confirmed/candidate/rejected status.

    Always CANDIDATE, never CONFIRMED: an external tool's own detection
    is not re-verified by this project's Judge/Reproducer the way a
    testcase-suite finding is, so claiming "confirmed" here would
    overstate the evidence -- the same reasoning the design doc already
    applies to SOURCE MODE static findings (reported as evidence-backed
    candidates, not confirmed ones).
    """
    findings: list[Finding] = []
    for pack_run in pack_runs:
        if pack_run.status != "ran" or pack_run.tool_id == "testcase_suite":
            continue
        summary = pack_run.summary or {}
        for item in summary.get("findings", []):
            findings.append(_promote_one(pack_run.tool_id, item, run_id, store))
    return findings


def _promote_one(tool_id: str, item: dict[str, object], run_id: str, store: SQLiteStore) -> Finding:
    is_secret = "redacted_secret" in item
    if is_secret:
        title = f"{item.get('detector', 'unknown')} secret exposure ({tool_id})"
        category = "secret_exposure"
        confidence = 1.0 if item.get("verified") else 0.5
    else:
        title = str(item.get("title") or f"{tool_id} finding")
        category = str(item.get("category") or "automated_scanning")
        confidence = float(item.get("detector_score") or 0.0)

    evidence_bundle = write_evidence_bundle(
        Path("evidence/raw"),
        Path("evidence/sanitized"),
        f"{run_id}_{tool_id}_{new_id('extfinding')}.json",
        dict(item),
    )
    evidence = store.record_evidence(
        run_id, f"{tool_id}_finding", evidence_bundle.sanitized_path, raw_path=evidence_bundle.raw_path
    )

    finding = Finding(
        run_id=run_id,
        testcase_id=f"{tool_id}:{category}",
        title=title,
        category=category,
        status=FindingStatus.CANDIDATE,
        confidence=confidence,
        severity="medium",
        evidence_ref=evidence.id,
        reproduction_spec={"type": "external_tool", "tool_id": tool_id, "raw": item},
    )
    store.insert_finding(finding)
    return finding
