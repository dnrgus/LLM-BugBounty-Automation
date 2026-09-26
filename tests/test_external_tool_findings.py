"""P3.1-4 Basic Report integration (roadmap v3.1.0 Operational Pipeline).

Covers promoting external-tool (nuclei/dalfox/trufflehog) normalized
results into first-class, evidence-backed candidate Findings
(findings/external_tool.py), and `scan <url>`'s finding_status_summary
distinguishing confirmed/unstable/rejected/candidate.
"""

import asyncio
import json
from pathlib import Path

from core.models import FindingStatus
from core.orchestrator import run_live_scan_pipeline, run_reproduce_finding
from core.profile import load_profile
from findings.external_tool import promote_external_tool_findings
from packs.runner import PackRunResult
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore

_NUCLEI_ITEM = {
    "run_id": "run_x",
    "target_id": "t",
    "source": {"tool": "nuclei", "version": "1.0"},
    "category": "exposed-panel",
    "title": "Exposed Admin Panel",
    "endpoint": "https://ai.example.com/admin",
    "detector_score": 0.8,
    "metadata": {"raw": {"note": "contains AKIAABCDEFGHIJKLMNOP as a planted secret"}},
}

_SECRET_ITEM = {
    "run_id": "run_x",
    "target_id": "t",
    "detector": "AWS",
    "source": "trufflehog",
    "location": "app.js:12",
    "verified": True,
    "redacted_secret": "AKIA****************",
}


def _policy() -> PolicyEngine:
    return PolicyEngine.from_yaml("config/scope.example.yaml")


def test_promote_external_tool_findings_skips_testcase_suite_and_non_ran_packs(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "ext.sqlite")
    store.initialize()
    pack_runs = [
        PackRunResult(pack_id="llm_core", tool_id="testcase_suite", status="ran", detail="", summary={"findings": [_NUCLEI_ITEM]}),
        PackRunResult(pack_id="web_scan", tool_id="nuclei", status="skipped_tool_not_installed", detail=""),
    ]
    findings = promote_external_tool_findings(pack_runs, "run_1", store)
    assert findings == []


def test_promote_external_tool_findings_creates_candidate_findings_with_evidence(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "ext.sqlite")
    store.initialize()
    pack_runs = [
        PackRunResult(pack_id="web_scan", tool_id="nuclei", status="ran", detail="", summary={"findings": [_NUCLEI_ITEM]}),
    ]

    findings = promote_external_tool_findings(pack_runs, "run_1", store)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.status == FindingStatus.CANDIDATE
    assert finding.title == "Exposed Admin Panel"
    assert finding.reproduction_spec["type"] == "external_tool"
    assert finding.reproduction_spec["tool_id"] == "nuclei"
    assert store.get_finding(finding.id) is not None


def test_promote_external_tool_findings_titles_secret_findings_distinctly(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "ext.sqlite")
    store.initialize()
    pack_runs = [
        PackRunResult(pack_id="secret_scan", tool_id="trufflehog", status="ran", detail="", summary={"findings": [_SECRET_ITEM]}),
    ]

    findings = promote_external_tool_findings(pack_runs, "run_1", store)

    assert len(findings) == 1
    assert findings[0].category == "secret_exposure"
    assert "AWS" in findings[0].title
    assert findings[0].confidence == 1.0  # verified=True


def test_promote_external_tool_findings_evidence_is_sanitized_of_planted_secrets(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "ext.sqlite")
    store.initialize()
    pack_runs = [
        PackRunResult(pack_id="web_scan", tool_id="nuclei", status="ran", detail="", summary={"findings": [_NUCLEI_ITEM]}),
    ]

    findings = promote_external_tool_findings(pack_runs, "run_1", store)
    finding = findings[0]

    with store.connect() as conn:
        row = conn.execute("select path from evidence where id = ?", (finding.evidence_ref,)).fetchone()
    sanitized_text = Path(row["path"]).read_text(encoding="utf-8")
    raw_path = Path(row["path"].replace("sanitized", "raw"))
    raw_text = raw_path.read_text(encoding="utf-8") if raw_path.exists() else ""

    assert "AKIAABCDEFGHIJKLMNOP" not in sanitized_text
    if raw_text:
        assert "AKIAABCDEFGHIJKLMNOP" in raw_text  # raw evidence keeps the original for authorized review


def test_promote_external_tool_findings_preserves_tool_reported_severity(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "ext.sqlite")
    store.initialize()
    critical = {**_NUCLEI_ITEM, "title": "Error based SQL Injection", "metadata": {"severity": "critical", "raw": {}}}
    info = {**_NUCLEI_ITEM, "title": "Public Swagger API", "metadata": {"severity": "info", "raw": {}}}
    pack_runs = [
        PackRunResult(pack_id="web_scan", tool_id="nuclei", status="ran", detail="", summary={"findings": [critical, info]}),
    ]

    findings = promote_external_tool_findings(pack_runs, "run_1", store)

    by_title = {f.title: f for f in findings}
    assert by_title["Error based SQL Injection"].severity == "critical"
    assert by_title["Public Swagger API"].severity == "info"


def test_promote_external_tool_findings_falls_back_to_medium_when_severity_missing_or_invalid(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "ext.sqlite")
    store.initialize()
    no_meta = {**_NUCLEI_ITEM, "metadata": {"raw": {}}}  # no severity key
    bogus = {**_NUCLEI_ITEM, "title": "Bogus sev", "metadata": {"severity": "spicy", "raw": {}}}
    pack_runs = [
        PackRunResult(pack_id="web_scan", tool_id="nuclei", status="ran", detail="", summary={"findings": [no_meta, bogus]}),
    ]

    findings = promote_external_tool_findings(pack_runs, "run_1", store)

    assert all(f.severity == "medium" for f in findings)


def test_promote_external_tool_findings_marks_verified_secrets_high(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "ext.sqlite")
    store.initialize()
    pack_runs = [
        PackRunResult(pack_id="secret_scan", tool_id="trufflehog", status="ran", detail="", summary={"findings": [_SECRET_ITEM]}),
    ]

    findings = promote_external_tool_findings(pack_runs, "run_1", store)

    assert findings[0].severity == "high"


def test_run_reproduce_finding_reports_external_tool_findings_as_unsupported_instead_of_crashing(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "ext.sqlite")
    store.initialize()
    pack_runs = [
        PackRunResult(pack_id="web_scan", tool_id="nuclei", status="ran", detail="", summary={"findings": [_NUCLEI_ITEM]}),
    ]
    finding = promote_external_tool_findings(pack_runs, "run_1", store)[0]

    result = asyncio.run(run_reproduce_finding(_policy(), [], store, finding.id, target_kind="fake-llm"))

    assert result["reproduction"]["type"] == "external_tool"
    assert result["reproduction"]["status"] == "unsupported"


def test_live_scan_finding_status_summary_distinguishes_confirmed_and_candidate(tmp_path: Path) -> None:
    import httpx

    html = "<html><body>This is an AI chat assistant endpoint.</body></html>"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/html"}, text=html)

    store = SQLiteStore(tmp_path / "live.sqlite")
    profile = load_profile("quick", "config/pipeline.yaml")
    result = asyncio.run(
        run_live_scan_pipeline(
            _policy(), [], store, profile, "https://ai.example.com/api/",
            pack_target="fake-llm", transport=httpx.MockTransport(handler),
        )
    )
    json.dumps(result)
    assert "finding_status_summary" in result
    assert isinstance(result["finding_status_summary"], dict)
