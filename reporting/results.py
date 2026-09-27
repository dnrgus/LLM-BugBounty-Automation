"""WP-08: write a scan's findings into a browsable, severity-sorted results
directory and produce the console summary (§14, §15, §37).

Layout under <output_dir>:
    summary.md, summary.json
    critical/ high/ medium/ low/ info/   -- confirmed/unstable findings
    needs_review/                        -- candidate / needs_review findings
    raw/                                 -- reserved for raw scan artifacts
Each finding gets its own folder with report.md, evidence.json, request.txt,
response.txt and reproduce.md.

This reuses the persisted Finding objects and their evidence; it does not
re-run anything.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from core.models import Finding, FindingStatus
from storage.sqlite import SQLiteStore

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITY_ORDER)}
_NEEDS_REVIEW_STATES = {FindingStatus.CANDIDATE, FindingStatus.NEEDS_REVIEW}


def _slug(text: str, limit: int = 40) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return (slug[:limit].strip("-")) or "finding"


def _severity_bucket(finding: Finding) -> str:
    return finding.severity if finding.severity in _SEVERITY_RANK else "info"


def _sort_key(finding: Finding) -> tuple[int, str]:
    return (_SEVERITY_RANK.get(finding.severity, len(SEVERITY_ORDER)), finding.title)


def _evidence_text(store: SQLiteStore, evidence_ref: str) -> str | None:
    with store.connect() as conn:
        row = conn.execute("select path from evidence where id = ?", (evidence_ref,)).fetchone()
    if not row:
        return None
    path = Path(row["path"])
    return path.read_text(encoding="utf-8") if path.exists() else None


def _nuclei_raw(finding: Finding) -> dict[str, Any]:
    spec = finding.reproduction_spec or {}
    item = spec.get("raw") if isinstance(spec, dict) else None
    if not isinstance(item, dict):
        return {}
    metadata = item.get("metadata")
    raw = metadata.get("raw") if isinstance(metadata, dict) else None
    return raw if isinstance(raw, dict) else {}


def _write_finding_files(folder: Path, finding: Finding, store: SQLiteStore) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# {finding.title}",
        "",
        f"- Severity: {finding.severity}",
        f"- External severity: {finding.external_severity or 'n/a'}",
        f"- Status: {finding.status.value}",
        f"- Confidence: {finding.confidence:.2f}",
        f"- Category: {finding.category}",
        f"- Source tool: {finding.source_tool or 'internal'}",
        f"- Endpoint: {finding.endpoint or 'n/a'}",
        f"- Method: {finding.method or 'n/a'}",
        f"- Finding ID: {finding.id}",
    ]
    (folder / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    evidence = _evidence_text(store, finding.evidence_ref)
    (folder / "evidence.json").write_text(evidence or "{}\n", encoding="utf-8")

    raw = _nuclei_raw(finding)
    (folder / "request.txt").write_text(str(raw.get("request") or "no request captured\n"), encoding="utf-8")
    (folder / "response.txt").write_text(str(raw.get("response") or "no response captured\n"), encoding="utf-8")

    reproduce = [
        f"# Reproduce: {finding.title}",
        "",
        f"- Tool: {finding.source_tool or 'internal pipeline'}",
        f"- Endpoint: {finding.endpoint or 'n/a'}",
        "",
    ]
    curl = raw.get("curl-command")
    if curl:
        reproduce += ["## Command", "", "```", str(curl), "```", ""]
    else:
        reproduce += ["Re-run `bugbounty reproduce " + finding.id + "` against the target.", ""]
    (folder / "reproduce.md").write_text("\n".join(reproduce) + "\n", encoding="utf-8")


def write_scan_results(
    output_dir: Path, findings: list[Finding], store: SQLiteStore, meta: dict[str, Any] | None = None
) -> dict[str, Any]:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "raw").mkdir(exist_ok=True)

    severity_counts = {name: 0 for name in SEVERITY_ORDER}
    needs_review_by_severity = {name: 0 for name in SEVERITY_ORDER}
    needs_review = 0
    index: list[dict[str, Any]] = []

    for number, finding in enumerate(sorted(findings, key=_sort_key), start=1):
        if finding.status == FindingStatus.REJECTED:
            continue
        if finding.status in _NEEDS_REVIEW_STATES:
            bucket = "needs_review"
            needs_review += 1
            needs_review_by_severity[_severity_bucket(finding)] += 1
        else:
            bucket = _severity_bucket(finding)
            severity_counts[bucket] += 1
        folder_name = f"FINDING-{number:03d}_{_slug(finding.title)}"
        _write_finding_files(output_dir / bucket / folder_name, finding, store)
        index.append(
            {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "external_severity": finding.external_severity,
                "status": finding.status.value,
                "source_tool": finding.source_tool,
                "endpoint": finding.endpoint,
                "bucket": bucket,
                "path": f"{bucket}/{folder_name}",
            }
        )

    summary = {
        "target": (meta or {}).get("target"),
        "severity_counts": severity_counts,
        "needs_review": needs_review,
        "needs_review_by_severity": needs_review_by_severity,
        "total": len(index),
        "findings": index,
        **{k: v for k, v in (meta or {}).items() if k != "target"},
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    (output_dir / "summary.md").write_text(_summary_md(summary), encoding="utf-8")

    return {
        "results_dir": str(output_dir),
        "severity_counts": severity_counts,
        "needs_review": needs_review,
        "needs_review_by_severity": needs_review_by_severity,
        "total": len(index),
    }


def _summary_md(summary: dict[str, Any]) -> str:
    lines = ["# Scan Summary", ""]
    if summary.get("target"):
        lines.append(f"- Target: {summary['target']}")
    lines.append(f"- Total findings: {summary['total']}")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for name in SEVERITY_ORDER:
        lines.append(f"| {name.capitalize()} | {summary['severity_counts'][name]} |")
    lines.append(f"| Needs Review | {summary['needs_review']} |")
    lines.append("")
    if summary["findings"]:
        lines += ["## Findings", "", "| Severity | Title | Tool | Endpoint | Path |", "| --- | --- | --- | --- | --- |"]
        for f in summary["findings"]:
            lines.append(
                f"| {f['severity']} | {f['title']} | {f['source_tool'] or '-'} | {f['endpoint'] or '-'} | {f['path']} |"
            )
    return "\n".join(lines) + "\n"


def render_console_summary(result: dict[str, Any]) -> str:
    """The terminal summary block (§15/§37), severity-ordered."""
    counts = result.get("severity_counts", {})
    lines = ["", "Scan complete.", ""]
    for name in SEVERITY_ORDER:
        lines.append(f"{name.capitalize():<8}: {counts.get(name, 0)}")
    lines.append("")
    nr = result.get("needs_review", 0)
    by_sev = result.get("needs_review_by_severity") or {}
    breakdown = ", ".join(f"{name}: {by_sev[name]}" for name in SEVERITY_ORDER if by_sev.get(name))
    lines.append(f"Needs Review : {nr}" + (f"  ({breakdown})" if breakdown else ""))
    if result.get("results_dir"):
        lines += ["", "Results saved to:", result["results_dir"]]
    return "\n".join(lines)
