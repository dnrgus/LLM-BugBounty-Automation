"""WP-08: severity-sorted results directory, per-finding files, summary,
and the console summary block."""

import json
from pathlib import Path

from core.models import Evidence, Finding, FindingStatus
from reporting.results import render_console_summary, write_scan_results
from storage.sqlite import SQLiteStore


def _store_with_evidence(tmp_path: Path) -> tuple[SQLiteStore, str]:
    store = SQLiteStore(tmp_path / "r.sqlite")
    store.initialize()
    ev_file = tmp_path / "ev.json"
    ev_file.write_text('{"note": "evidence body"}', encoding="utf-8")
    evidence = store.record_evidence("run_1", "nuclei_finding", ev_file)
    return store, evidence.id


def _finding(evidence_id: str, **kw) -> Finding:
    base = dict(
        run_id="run_1", testcase_id="nuclei:sqli", title="Error based SQL Injection", category="sqli",
        status=FindingStatus.CANDIDATE, confidence=1.0, severity="critical", evidence_ref=evidence_id,
        source_tool="nuclei", endpoint="http://127.0.0.1:3000/rest/products/search?q=x",
        external_severity="critical",
        reproduction_spec={"type": "external_tool", "tool_id": "nuclei",
                           "raw": {"metadata": {"raw": {"request": "GET /x", "response": "HTTP/1.1 500"}}}},
    )
    base.update(kw)
    return Finding(**base)


def test_write_scan_results_buckets_candidate_into_needs_review(tmp_path: Path) -> None:
    store, ev = _store_with_evidence(tmp_path)
    out = tmp_path / "out"
    info = write_scan_results(out, [_finding(ev)], store, {"target": "http://127.0.0.1:3000"})

    assert info["needs_review"] == 1
    assert info["needs_review_by_severity"]["critical"] == 1
    assert info["severity_counts"]["critical"] == 0  # candidate isn't auto-confirmed (§12)
    folder = out / "needs_review" / "FINDING-001_error-based-sql-injection"
    assert (folder / "report.md").exists()
    assert (folder / "evidence.json").read_text(encoding="utf-8") == '{"note": "evidence body"}'
    assert "GET /x" in (folder / "request.txt").read_text(encoding="utf-8")
    assert (out / "summary.json").exists()


def test_write_scan_results_buckets_confirmed_by_severity(tmp_path: Path) -> None:
    store, ev = _store_with_evidence(tmp_path)
    out = tmp_path / "out"
    confirmed = _finding(ev, status=FindingStatus.CONFIRMED, severity="high", title="Confirmed XSS")
    info = write_scan_results(out, [confirmed], store, {"target": "t"})

    assert info["severity_counts"]["high"] == 1
    assert info["needs_review"] == 0
    assert (out / "high" / "FINDING-001_confirmed-xss" / "report.md").exists()


def test_rejected_findings_are_not_written(tmp_path: Path) -> None:
    store, ev = _store_with_evidence(tmp_path)
    out = tmp_path / "out"
    info = write_scan_results(out, [_finding(ev, status=FindingStatus.REJECTED)], store, {})
    assert info["total"] == 0


def test_summary_json_lists_findings_with_severity(tmp_path: Path) -> None:
    store, ev = _store_with_evidence(tmp_path)
    out = tmp_path / "out"
    write_scan_results(out, [_finding(ev)], store, {"target": "t"})
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["findings"][0]["severity"] == "critical"
    assert summary["findings"][0]["source_tool"] == "nuclei"


def test_console_summary_shows_ordered_counts_and_path() -> None:
    text = render_console_summary(
        {"severity_counts": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
         "needs_review": 2, "needs_review_by_severity": {"critical": 1, "info": 1, "high": 0, "medium": 0, "low": 0},
         "results_dir": "/x/out"}
    )
    assert "Scan complete." in text
    assert "Critical: 1" in text
    assert "Needs Review : 2" in text
    assert "critical: 1" in text
    assert text.index("Critical") < text.index("High") < text.index("Info")
    assert "/x/out" in text
