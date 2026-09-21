import json
from pathlib import Path

from reporting.evidence import write_evidence_bundle
from reporting.sanitizer import sanitize_text


def test_sanitize_text_redacts_sensitive_values() -> None:
    text = "Authorization: Bearer abc123\nCookie: sid=secret\nuser@example.com\nCANARY-SECRET-123"
    sanitized, redactions = sanitize_text(text)
    assert "abc123" not in sanitized
    assert "sid=secret" not in sanitized
    assert "user@example.com" not in sanitized
    assert "CANARY-SECRET-123" not in sanitized
    assert {item.name for item in redactions} == {"authorization_bearer", "cookie", "email", "canary"}


def test_evidence_bundle_writes_hashes_and_redaction_log(tmp_path: Path) -> None:
    bundle = write_evidence_bundle(
        tmp_path / "raw",
        tmp_path / "sanitized",
        "evidence.json",
        {"header": "Authorization: Bearer abc123", "marker": "CANARY-SECRET-123"},
    )
    assert bundle.raw_path.exists()
    assert bundle.sanitized_path.exists()
    assert bundle.redaction_log_path.exists()
    assert bundle.raw_sha256 != bundle.sanitized_sha256
    assert "authorization_bearer" in bundle.redaction_log_path.read_text(encoding="utf-8")
    assert "[REDACTED]" in bundle.sanitized_path.read_text(encoding="utf-8")


def test_sample_pipeline_writes_json_report(tmp_path: Path) -> None:
    import asyncio

    from core.orchestrator import run_sample_pipeline
    from scope.policy import PolicyEngine
    from storage.sqlite import SQLiteStore
    from testcase.loader import load_testcases

    result = asyncio.run(
        run_sample_pipeline(
            PolicyEngine.from_yaml("config/scope.example.yaml"),
            load_testcases("testcase/suites/basic.yaml"),
            SQLiteStore(tmp_path / "report.sqlite"),
            target_kind="fake-llm",
        )
    )
    json_reports = [Path(path) for path in result["reports"] if path.endswith(".json")]
    assert json_reports
    data = json.loads(json_reports[0].read_text(encoding="utf-8"))
    assert data["status"] == "confirmed"
    assert data["reproduction"]["success_rate"] == 1.0
    assert data["evidence"]["sanitized_sha256"]
