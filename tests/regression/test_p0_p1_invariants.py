"""P4.7 WP-08 (v5.0 plan 7.3): the P0/P1 invariants, as one named suite
(`pytest -m p0`, `pytest -m p1`). P0 = crash, scope bypass, evidence
damage, dangerous-request misclassification; P1 = CLI flow breaks,
reproduction failures."""

import asyncio
import json
import os
from pathlib import Path

import httpx
import pytest

from cli import main
from reporting.evidence import write_evidence_bundle
from reporting.integrity import build_run_manifest
from scope.policy import PolicyEngine, method_risk
from source.audit import audit_source
from source.endpoints import EndpointSpec
from storage.sqlite import SQLiteStore
from validation.auth_contexts import AuthContextSet, TesterAccount
from validation.auth_validator import AuthContext
from validation.endpoint_validator import validate_endpoint, validate_endpoint_request
from validation.object_access_validator import validate_object_access
from validation.workflow import build_scan_artifact, run_validate, write_validation_report

FIXTURE = Path("tests/fixtures/source/rest_api_app").resolve()


def _policy(**testing: object) -> PolicyEngine:
    return PolicyEngine({"scope": {"domains": ["in.example.com"]}, "testing": {"automated_scanning": True, **testing}})


def _recording(calls: list[httpx.Request], responder=None) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return responder(request) if responder else httpx.Response(200, json={"ok": True})

    return httpx.MockTransport(handler)


# --- P0: crash --------------------------------------------------------------


@pytest.mark.p0
def test_hostile_source_tree_never_crashes_audit(tmp_path: Path) -> None:
    (tmp_path / "deep.py").write_text("x = " + "(" * 5000 + "1" + ")" * 5000 + "\n", encoding="utf-8")
    (tmp_path / "deep_call.py").write_text(
        "from flask import request\n@app.get('/a')\ndef h():\n    return " + "f(" * 3000 + "request.args" + ")" * 3000 + "\n",
        encoding="utf-8",
    )
    (tmp_path / "binary.py").write_bytes(os.urandom(4096))
    (tmp_path / "badutf.js").write_bytes(b'app.get("/x", (req,res)=>{ \xff\xfe exec(req.query.a) })')
    (tmp_path / "empty.ts").write_text("", encoding="utf-8")
    (tmp_path / "big.py").write_text("def f(a):\n    return a\n" * 20000, encoding="utf-8")
    try:
        os.symlink(tmp_path, tmp_path / "loop")
    except OSError:
        pass
    result = audit_source(tmp_path)
    assert result["files_scanned"] >= 5


# --- P0: scope bypass ---------------------------------------------------------


@pytest.mark.p0
def test_out_of_scope_targets_are_never_requested_by_any_validator() -> None:
    calls: list[httpx.Request] = []
    transport = _recording(calls)
    policy = _policy(state_changing_requests="allowed", destructive_actions=True)
    asyncio.run(validate_endpoint("https://out.example.net/a", "GET", policy, transport=transport))
    for method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
        asyncio.run(validate_endpoint_request("https://out.example.net/a", method, policy, example_body={}, transport=transport))
    accounts = AuthContextSet(
        [
            TesterAccount(AuthContext(id=i, principal_label=i, credential_source="env", headers={}), owned_objects={"note_id": n})
            for i, n in (("a", "1"), ("b", "2"))
        ]
    )
    spec = EndpointSpec(method="GET", path="/api/notes/<int:note_id>", path_params=["note_id"])
    asyncio.run(validate_object_access(spec, "https://out.example.net", accounts, policy, transport=transport))
    assert calls == []


@pytest.mark.p0
def test_redirect_to_out_of_scope_host_is_not_followed() -> None:
    calls: list[httpx.Request] = []

    def responder(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://out.example.net/steal"})

    evidence = asyncio.run(validate_endpoint("https://in.example.com/a", "GET", _policy(), transport=_recording(calls, responder)))
    assert {call.url.host for call in calls} == {"in.example.com"}
    assert "out of scope" in str(evidence.observations[0].error)


# --- P0: dangerous request misclassification ------------------------------------------


@pytest.mark.p0
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "PROPFIND", "post"])
def test_non_read_methods_are_never_sent_under_default_policy(method: str) -> None:
    assert method_risk(method) != "read_only"
    calls: list[httpx.Request] = []
    asyncio.run(validate_endpoint_request("https://in.example.com/a", method, _policy(), example_body={"x": 1}, transport=_recording(calls)))
    assert calls == []


@pytest.mark.p0
def test_example_scope_blocks_delete_even_if_everything_else_is_allowed() -> None:
    engine = PolicyEngine.from_yaml("config/scope.example.yaml")
    engine.config["testing"]["state_changing_requests"] = "allowed"
    engine.config["testing"]["destructive_actions"] = True
    assert engine.decide_method("DELETE").mode == "block"


# --- P0: evidence damage / redaction ------------------------------------------


@pytest.mark.p0
def test_tampered_evidence_is_detected_and_flagged_in_reports(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    store = SQLiteStore(tmp_path / "v.sqlite")
    result = asyncio.run(run_validate(build_scan_artifact(FIXTURE), "https://in.example.com", _policy(), store, transport=_recording([])))
    run_id = result["run_id"]
    assert not build_run_manifest(store, run_id).any_tamper_detected

    finding_id = result["findings"][0]["finding_id"]
    evidence_id = store.get_finding(finding_id).evidence_ref
    evidence_path = next(Path(row["path"]) for row in store.list_evidence(run_id) if row["id"] == evidence_id)
    evidence_path.write_text('{"reason": "forged"}', encoding="utf-8")

    summary = write_validation_report(store, run_id, tmp_path / "reports")
    assert evidence_id in summary["integrity"]["tamper_detected"]
    report = json.loads((tmp_path / "reports" / f"{finding_id}.json").read_text(encoding="utf-8"))
    assert report["evidence"]["tamper_detected"] is True
    assert report["reason"] is None  # forged content is never quoted as the verdict reason


@pytest.mark.p0
def test_sanitized_evidence_redacts_credentials(tmp_path: Path) -> None:
    bundle = write_evidence_bundle(
        tmp_path / "raw", tmp_path / "sanitized", "e.json",
        {"headers": "Authorization: Bearer abc.def-123", "key": "api_key=sk_live_123456", "canary": "CANARY-SECRET-123"},
    )
    sanitized = bundle.sanitized_path.read_text(encoding="utf-8")
    for secret in ("abc.def-123", "sk_live_123456", "CANARY-SECRET-123"):
        assert secret not in sanitized


# --- P1: CLI flow ------------------------------------------------------------


@pytest.mark.p1
def test_cli_flow_scan_validate_report_reproduce_has_no_break(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.chdir(tmp_path)
    scope = tmp_path / "scope.yaml"
    scope.write_text("scope: {domains: [in.example.com]}\ntesting: {automated_scanning: true}\n", encoding="utf-8")
    assert main(["scan", "--source", str(FIXTURE), "--artifact", "s.json"]) == 0
    capsys.readouterr()
    assert main(["validate", "--artifact", "s.json", "--base-url", "https://unrouted.invalid", "--scope", str(scope), "--db", "v.sqlite"]) == 0
    validated = json.loads(capsys.readouterr().out)
    assert main(["report", "--run-id", validated["run_id"], "--db", "v.sqlite", "--out", "r"]) == 0
    capsys.readouterr()
    assert main(["reproduce", validated["findings"][0]["finding_id"], "--db", "v.sqlite", "--scope", str(scope), "--attempts", "1"]) == 0


@pytest.mark.p1
def test_llm_reproduction_still_confirms_representative_finding(tmp_path: Path) -> None:
    from core.orchestrator import run_sample_pipeline
    from testcase.loader import load_testcases

    store = SQLiteStore(tmp_path / "s.sqlite")
    result = asyncio.run(
        run_sample_pipeline(PolicyEngine.from_yaml("config/scope.example.yaml"), load_testcases("testcase/suites/basic.yaml"), store)
    )
    (finding,) = [f for f in store.list_findings([result["run_id"]]) if f.status.value == "confirmed"]
    (row,) = store.list_reproductions(finding.id)
    assert row["successes"] == row["attempts"] > 0
