"""P4.5 WP-03 (v5.0 plan 5.3/5.4): scan -> validate -> reproduce -> report
without breaks, with state-changing methods reaching the gate."""

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from cli import main
from core.models import FindingStatus
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from validation.auth_contexts import AuthContextSet, TesterAccount
from validation.auth_validator import AuthContext
from validation.workflow import (
    build_scan_artifact,
    load_scan_artifact,
    reproduce_validation_finding,
    run_validate,
    write_artifact,
    write_validation_report,
)

FIXTURE = Path("tests/fixtures/source/rest_api_app").resolve()


def _policy(**testing: object) -> PolicyEngine:
    return PolicyEngine(
        {"scope": {"domains": ["api.example.com"]}, "testing": {"automated_scanning": True, **testing}}
    )


def _contexts() -> AuthContextSet:
    def account(ident: str, note_id: str) -> TesterAccount:
        return TesterAccount(
            context=AuthContext(id=ident, principal_label=ident, credential_source="env", headers={"Authorization": f"Bearer {ident}"}),
            owned_objects={"note_id": note_id},
        )

    return AuthContextSet([account("user_a", "101"), account("user_b", "202")])


def _transport(calls: list[httpx.Request]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"id": 101, "owner": "user_a"})

    return httpx.MockTransport(handler)


def test_scan_artifact_contains_inventory_and_round_trips(tmp_path: Path) -> None:
    artifact = build_scan_artifact(FIXTURE)
    path = write_artifact(tmp_path / "scan.json", artifact)
    loaded = load_scan_artifact(path)
    methods = sorted({entry["method"] for entry in loaded["endpoint_inventory"]})
    assert methods == ["DELETE", "GET", "PATCH", "POST", "PUT"]


def test_load_scan_artifact_rejects_other_json(tmp_path: Path) -> None:
    path = tmp_path / "x.json"
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError):
        load_scan_artifact(path)


def test_full_flow_with_two_accounts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    store = SQLiteStore(tmp_path / "v.sqlite")
    calls: list[httpx.Request] = []
    artifact = build_scan_artifact(FIXTURE)

    result = asyncio.run(
        run_validate(artifact, "https://api.example.com", _policy(), store, auth_contexts=_contexts(),
                     key_fields=["owner"], transport=_transport(calls))
    )
    # Only read-only requests were sent; state-changing ones were planned (dry_run) and recorded.
    assert {call.method for call in calls} == {"GET"}
    modes = {(r["method"], r["execution_mode"]) for r in result["request_validations"]}
    assert ("POST", "dry_run") in modes and ("PUT", "dry_run") in modes and ("PATCH", "dry_run") in modes
    assert ("DELETE", "block") not in modes  # scope example has no blocked_actions here
    assert result["findings_by_status"] == {"confirmed": 1}

    finding_id = result["findings"][0]["finding_id"]
    finding = store.get_finding(finding_id)
    assert finding is not None and finding.status is FindingStatus.CONFIRMED
    assert "Bearer" not in json.dumps(finding.reproduction_spec)

    reproduction = asyncio.run(
        reproduce_validation_finding(finding, _policy(), store, _contexts(), attempts=2, transport=_transport(calls))
    )
    assert reproduction["reproduction"]["successes"] == 2
    assert reproduction["reproduction"]["status"] == "confirmed"

    summary = write_validation_report(store, result["run_id"], tmp_path / "reports")
    assert summary["findings_by_status"] == {"confirmed": 1}
    report = json.loads((tmp_path / "reports" / f"{finding_id}.json").read_text(encoding="utf-8"))
    assert report["evidence"]["sha256"]
    assert report["reproductions"] == [{"attempts": 2, "successes": 2, "status": "confirmed"}]
    assert report["reproduction_steps"] and report["limitations"]
    markdown = (tmp_path / "reports" / f"{finding_id}.md").read_text(encoding="utf-8")
    assert "재현 절차" in markdown and "Evidence SHA-256" in markdown


def test_validate_without_auth_contexts_stops_safely_with_reason(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    store = SQLiteStore(tmp_path / "v.sqlite")
    calls: list[httpx.Request] = []
    result = asyncio.run(
        run_validate(build_scan_artifact(FIXTURE), "https://api.example.com", _policy(), store, transport=_transport(calls))
    )
    # No path-param endpoint was requested with a guessed id.
    assert all("/api/notes/" not in str(call.url) for call in calls)
    (object_result,) = result["object_access_validations"]
    assert object_result["verdict"] == "needs_review"
    assert "no --auth-contexts" in object_result["reason"]
    assert result["findings_by_status"] == {"needs_review": 1}


def test_state_changing_policy_cannot_be_bypassed_by_captured_body(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    capture = tmp_path / "capture.json"
    capture.write_text(json.dumps([{"method": "POST", "path": "/api/notes", "body": {"title": "t"}}]), encoding="utf-8")
    calls: list[httpx.Request] = []
    asyncio.run(
        run_validate(build_scan_artifact(FIXTURE, captured_requests=capture), "https://api.example.com", _policy(),
                     SQLiteStore(tmp_path / "v.sqlite"), transport=_transport(calls))
    )
    assert "POST" not in {call.method for call in calls}


def test_cli_scan_validate_report_reproduce_chain(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.chdir(tmp_path)
    scope = tmp_path / "scope.yaml"
    # Out-of-scope base url: validate must run end to end without sending anything.
    scope.write_text("scope: {domains: [api.example.com]}\ntesting: {automated_scanning: true}\n", encoding="utf-8")

    assert main(["scan", "--source", str(FIXTURE), "--artifact", "scan.json"]) == 0
    capsys.readouterr()
    assert main(["validate", "--artifact", "scan.json", "--base-url", "https://other.example.net", "--scope", str(scope), "--db", "v.sqlite"]) == 0
    validated = json.loads(capsys.readouterr().out)
    assert all(r["execution_mode"] in {"block", "review_required"} for r in validated["request_validations"])

    assert main(["report", "--run-id", validated["run_id"], "--db", "v.sqlite", "--out", "reports"]) == 0
    reported = json.loads(capsys.readouterr().out)
    assert reported["findings_by_status"] == {"needs_review": 1}

    finding_id = validated["findings"][0]["finding_id"]
    assert main(["reproduce", finding_id, "--db", "v.sqlite", "--scope", str(scope), "--attempts", "1"]) == 0
    reproduced = json.loads(capsys.readouterr().out)
    assert reproduced["reproduction"]["status"] == "needs_review"
