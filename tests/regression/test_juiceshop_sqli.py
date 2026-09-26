"""WP-10 regression (§31): the confirmed Juice Shop case.

A nuclei DAST run against /rest/products/search?q= reports a critical
error-based SQL injection. This locks in the full chain without needing a
live Juice Shop server:

    nuclei JSON -> normalize -> external finding -> critical severity kept
    -> written into the results tree under its severity/needs_review folder.
"""

from pathlib import Path

from adapters.scanner.nuclei import NucleiAdapter
from findings.external_tool import promote_external_tool_findings
from packs.runner import PackRunResult
from reporting.results import write_scan_results
from storage.sqlite import SQLiteStore

_FIXTURE = Path("tests/fixtures/regression/juiceshop_sqli_nuclei.jsonl")


def _pack_run() -> PackRunResult:
    findings = NucleiAdapter().parse_file(_FIXTURE, run_id="run_reg", target_id="juiceshop")
    return PackRunResult(
        pack_id="web_scan", tool_id="nuclei", status="ran", detail="",
        summary={"count": len(findings), "findings": [f.to_dict() for f in findings]},
    )


def test_juiceshop_sqli_normalizes_to_critical_external_finding(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "reg.sqlite")
    store.initialize()

    findings = promote_external_tool_findings([_pack_run()], "run_reg", store)

    by_title = {f.title: f for f in findings}
    sqli = by_title["Error based SQL Injection"]
    assert sqli.severity == "critical"
    assert sqli.external_severity == "critical"
    assert sqli.source_tool == "nuclei"
    assert sqli.category == "sqli"
    assert "search" in (sqli.endpoint or "")
    # the info exposure must not be inflated
    assert by_title["Public Swagger API - Detect"].severity == "info"


def test_juiceshop_sqli_is_written_into_results_tree(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "reg.sqlite")
    store.initialize()
    findings = promote_external_tool_findings([_pack_run()], "run_reg", store)

    out = tmp_path / "out"
    info = write_scan_results(out, findings, store, {"target": "http://localhost:3000"})

    # external-tool findings are candidates -> needs_review, but the critical
    # severity is preserved and surfaced in the breakdown.
    assert info["needs_review_by_severity"]["critical"] == 1
    sqli_dir = out / "needs_review" / "FINDING-001_error-based-sql-injection"
    assert (sqli_dir / "report.md").exists()
    report = (sqli_dir / "report.md").read_text(encoding="utf-8")
    assert "Severity: critical" in report
    assert "sqli" in (sqli_dir / "report.md").read_text(encoding="utf-8").lower()
