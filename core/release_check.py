from __future__ import annotations

import asyncio
import io
import json
import os
import tempfile
import traceback
from contextlib import contextmanager, redirect_stdout
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

import httpx

# P5.0 WP-10 (v5.0 plan 8.3): the v5.0.0 release gate as an executable,
# offline checklist. Every gate uses local fixtures, fake targets and
# in-process mock transports -- no external network, no real target.

REPO_ROOT = Path(__file__).resolve().parent.parent
_FIXTURE = REPO_ROOT / "tests/fixtures/source/rest_api_app"


@dataclass(frozen=True)
class GateResult:
    id: str
    title: str
    passed: bool
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "title": self.title, "passed": self.passed, "detail": self.detail}


@contextmanager
def _scratch() -> Iterator[Path]:
    previous = Path.cwd()
    with tempfile.TemporaryDirectory() as directory:
        os.chdir(directory)
        try:
            yield Path(directory)
        finally:
            os.chdir(previous)


def _policy(**testing: object):
    from scope.policy import PolicyEngine

    return PolicyEngine({"scope": {"domains": ["app.test"]}, "testing": {"automated_scanning": True, **testing}})


def _recorder(calls: list[httpx.Request], responder: Callable[[httpx.Request], httpx.Response] | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return responder(request) if responder else httpx.Response(200, json={"ok": True})

    return httpx.MockTransport(handler)


def _accounts():
    from validation.auth_contexts import AuthContextSet, TesterAccount
    from validation.auth_validator import AuthContext

    return AuthContextSet(
        [
            TesterAccount(AuthContext(id=ident, principal_label=ident, credential_source="env", headers={"Authorization": f"Bearer {ident}"}),
                          owned_objects={"note_id": note})
            for ident, note in (("tester_a", "101"), ("tester_b", "202"))
        ]
    )


def _notes_app(enforce_ownership: bool) -> Callable[[httpx.Request], httpx.Response]:
    """In-process stand-in for a notes API owned by two test accounts."""
    owners = {"101": "tester_a", "202": "tester_b"}

    def respond(request: httpx.Request) -> httpx.Response:
        caller = request.headers.get("Authorization", "").removeprefix("Bearer ")
        note_id = request.url.path.rstrip("/").rsplit("/", 1)[-1]
        owner = owners.get(note_id)
        if owner is None:
            return httpx.Response(404, json={"error": "not found"})
        if enforce_ownership and caller != owner:
            return httpx.Response(403, json={"error": "forbidden"})
        return httpx.Response(200, json={"id": int(note_id), "owner": owner})

    return respond


# --- gates ---------------------------------------------------------------------------


def gate_end_to_end() -> str:
    from cli import main

    with _scratch() as scratch:
        scope = scratch / "scope.yaml"
        scope.write_text("scope: {domains: [app.test]}\ntesting: {automated_scanning: true}\n", encoding="utf-8")
        assert main(["scan", "--source", str(_FIXTURE), "--artifact", "scan.json"]) == 0
        assert main(["sample-run", "--db", "sample.sqlite", "--scope", str(REPO_ROOT / "config/scope.example.yaml"),
                     "--testcases", str(REPO_ROOT / "testcase/suites/basic.yaml")]) == 0
        from storage.sqlite import SQLiteStore
        from validation.workflow import load_scan_artifact, reproduce_validation_finding, run_validate, write_validation_report

        store = SQLiteStore("v.sqlite")
        result = asyncio.run(
            run_validate(load_scan_artifact("scan.json"), "https://app.test", _policy(), store, auth_contexts=_accounts(),
                         key_fields=["owner"], transport=_recorder([], _notes_app(enforce_ownership=True)))
        )
        summary = write_validation_report(store, result["run_id"], "reports")
        finding = store.get_finding(result["findings"][0]["finding_id"])
        reproduction = asyncio.run(
            reproduce_validation_finding(finding, _policy(), store, _accounts(), attempts=2,
                                         transport=_recorder([], _notes_app(enforce_ownership=True)))
        )
        assert summary["findings"] and reproduction["reproduction"]["attempts"] == 2
    return "scan -> sample-run -> validate -> report -> reproduce completed on the sample project"


def gate_scope_blocked() -> str:
    from validation.endpoint_validator import validate_endpoint, validate_endpoint_request
    from validation.object_access_validator import validate_object_access
    from source.endpoints import EndpointSpec

    calls: list[httpx.Request] = []
    policy = _policy(state_changing_requests="allowed", destructive_actions=True)
    asyncio.run(validate_endpoint("https://outside.test/a", "GET", policy, transport=_recorder(calls)))
    for method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
        asyncio.run(validate_endpoint_request("https://outside.test/a", method, policy, example_body={}, transport=_recorder(calls)))
    spec = EndpointSpec(method="GET", path="/api/notes/<int:note_id>", path_params=["note_id"])
    asyncio.run(validate_object_access(spec, "https://outside.test", _accounts(), policy, transport=_recorder(calls)))
    assert calls == [], f"{len(calls)} out-of-scope request(s) sent"
    return "0 requests sent to an out-of-scope host across every validator"


def gate_state_changing_gated() -> str:
    from validation.endpoint_validator import validate_endpoint_request

    calls: list[httpx.Request] = []
    modes = []
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        evidence = asyncio.run(
            validate_endpoint_request("https://app.test/a", method, _policy(), example_body={"x": 1}, transport=_recorder(calls))
        )
        modes.append(f"{method}={evidence.execution_mode}")
    assert calls == [], "a state-changing request was sent under the default policy"
    return "default policy: " + ", ".join(modes) + "; 0 requests sent"


def gate_llm_reproducible() -> str:
    from core.orchestrator import run_sample_pipeline
    from scope.policy import PolicyEngine
    from storage.sqlite import SQLiteStore
    from testcase.loader import load_testcases

    details = []
    with _scratch():
        for target in ("fake-llm", "fake-rag"):
            store = SQLiteStore(f"{target}.sqlite")
            result = asyncio.run(
                run_sample_pipeline(PolicyEngine.from_yaml(REPO_ROOT / "config/scope.example.yaml"),
                                    load_testcases(REPO_ROOT / "testcase/suites/basic.yaml"), store, target_kind=target)
            )
            confirmed = [f for f in store.list_findings([result["run_id"]]) if f.status.value == "confirmed"]
            assert confirmed, f"{target}: no confirmed finding"
            for finding in confirmed:
                (row,) = store.list_reproductions(finding.id)
                assert row["successes"] == row["attempts"] > 0, f"{target}: {finding.testcase_id} not fully reproduced"
                details.append(f"{target}:{finding.testcase_id} {row['successes']}/{row['attempts']}")
    return "; ".join(details)


def gate_object_access_with_test_accounts() -> str:
    from source.endpoints import EndpointSpec
    from validation.object_access_validator import validate_object_access

    spec = EndpointSpec(method="GET", path="/api/notes/<int:note_id>", path_params=["note_id"])
    enforced = asyncio.run(validate_object_access(spec, "https://app.test", _accounts(), _policy(), key_fields=["owner"],
                                                  transport=_recorder([], _notes_app(enforce_ownership=True))))
    broken = asyncio.run(validate_object_access(spec, "https://app.test", _accounts(), _policy(), key_fields=["owner"],
                                                transport=_recorder([], _notes_app(enforce_ownership=False))))
    from validation.auth_contexts import AuthContextSet

    single = asyncio.run(validate_object_access(spec, "https://app.test", AuthContextSet(_accounts().accounts[:1]), _policy(),
                                                transport=_recorder([])))
    assert (enforced.verdict, broken.verdict, single.verdict) == ("rejected", "confirmed", "needs_review"), (
        enforced.verdict, broken.verdict, single.verdict)
    return "ownership enforced -> rejected; not enforced -> confirmed; one account only -> needs_review"


def gate_dataflow_regression() -> str:
    from benchmarks.dataset import compare_to_baseline, load_dataset, run_dataset
    from benchmarks.ground_truth import load_ground_truth_corpus
    from benchmarks.matcher import match_findings_to_ground_truth
    from benchmarks.metrics import aggregate_accuracy_metrics
    from source.audit import collect_source_items

    previous = Path.cwd()
    os.chdir(REPO_ROOT)
    try:
        metrics = []
        for entry in load_ground_truth_corpus("benchmarks/corpus"):
            _, items = collect_source_items(entry.fixture_path)
            metrics.append(match_findings_to_ground_truth(items, entry.findings).metrics)
        aggregated = aggregate_accuracy_metrics(metrics)
        report = run_dataset(load_dataset("benchmarks/datasets/manifest.yaml"))
        regressions = compare_to_baseline(report, json.loads(Path("benchmarks/baselines/baseline.json").read_text(encoding="utf-8")))
    finally:
        os.chdir(previous)
    assert aggregated.recall >= 0.85 and aggregated.precision >= 0.85, aggregated.to_dict()
    assert not regressions, regressions
    return (f"quality-gate precision {aggregated.precision:.2f} / recall {aggregated.recall:.2f}; "
            f"benchmark vs baseline: 0 regressions")


def gate_evidence_integrity() -> str:
    from reporting.evidence import write_evidence_bundle
    from reporting.integrity import build_run_manifest
    from storage.sqlite import SQLiteStore

    with _scratch() as scratch:
        store = SQLiteStore("e.sqlite")
        store.initialize()
        bundle = write_evidence_bundle(scratch / "raw", scratch / "sanitized", "e.json",
                                       {"h": "Authorization: Bearer tok.abc-1", "canary": "CANARY-SECRET-123"})
        store.record_evidence("run_gate", "gate", bundle.sanitized_path, raw_path=bundle.raw_path)
        assert not build_run_manifest(store, "run_gate").any_tamper_detected
        sanitized = bundle.sanitized_path.read_text(encoding="utf-8")
        assert "tok.abc-1" not in sanitized and "CANARY-SECRET-123" not in sanitized, "redaction failed"
        bundle.raw_path.write_text("{}", encoding="utf-8")
        assert build_run_manifest(store, "run_gate").any_tamper_detected, "tamper not detected"
    return "hashes verified, credentials/canary redacted, modified raw evidence detected"


def gate_report_complete() -> str:
    from core.contract import REQUIRED_REPORT_FIELDS
    from storage.sqlite import SQLiteStore
    from validation.workflow import build_scan_artifact, run_validate, write_validation_report

    with _scratch():
        store = SQLiteStore("v.sqlite")
        result = asyncio.run(run_validate(build_scan_artifact(_FIXTURE), "https://app.test", _policy(), store,
                                          auth_contexts=_accounts(), key_fields=["owner"],
                                          transport=_recorder([], _notes_app(enforce_ownership=False))))
        write_validation_report(store, result["run_id"], "reports")
        for entry in result["findings"]:
            report = json.loads(Path("reports", f"{entry['finding_id']}.json").read_text(encoding="utf-8"))
            missing = [name for name in REQUIRED_REPORT_FIELDS if report.get(name) in (None, "", [])
                       and name != "reproductions"]
            assert not missing, f"{entry['finding_id']}: missing {missing}"
            assert report["evidence"]["sha256"] and report["reproduction_steps"]
    return f"{len(result['findings'])} report(s) with reason, evidence hash, reproduction steps and limitations"


def gate_known_limitations_documented() -> str:
    for name in ("docs/KNOWN_LIMITATIONS.md", "docs/SUPPORT_MATRIX.md", "docs/SCHEMAS.md", "docs/CLI.md"):
        path = REPO_ROOT / name
        assert path.exists() and len(path.read_text(encoding="utf-8").strip()) > 200, f"{name} missing or empty"
    return "known limitations, support matrix, schemas and CLI reference present"


def gate_benchmark_scope_documented() -> str:
    limitations = (REPO_ROOT / "docs/KNOWN_LIMITATIONS.md").read_text(encoding="utf-8")
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "no external real-world vulnerable applications" in limitations
    assert "외부 실제 취약 앱은 포함되어 있지 않습니다" in readme and "| overall (holdout 제외) |" in readme
    return "benchmark numbers published with dataset scope (targets, ground-truth size, holdout, no external apps)"


GATES: tuple[tuple[str, str, Callable[[], str]], ...] = (
    ("G1", "기본 설치 후 샘플 프로젝트에서 end-to-end 실행 가능", gate_end_to_end),
    ("G2", "scope 밖 대상은 실행 전에 차단", gate_scope_blocked),
    ("G3", "상태 변경 요청은 정책 없이 자동 실행되지 않음", gate_state_changing_gated),
    ("G4", "LLM finding 최소 대표 세트가 재현 가능", gate_llm_reproducible),
    ("G5", "Auth/BOLA 비교 validation이 테스트 계정 환경에서 동작", gate_object_access_with_test_accounts),
    ("G6", "Python/JS-TS 대표 dataflow regression 통과", gate_dataflow_regression),
    ("G7", "evidence hash 검증 및 redaction 테스트 통과", gate_evidence_integrity),
    ("G8", "report 생성 후 finding 근거와 재현 절차가 누락되지 않음", gate_report_complete),
    ("G9", "known limitation 문서 작성 완료", gate_known_limitations_documented),
    ("G10", "benchmark 결과와 데이터셋 범위 명시 완료", gate_benchmark_scope_documented),
)


def run_release_check(only: list[str] | None = None) -> dict[str, object]:
    results: list[GateResult] = []
    for gate_id, title, gate in GATES:
        if only and gate_id not in only:
            continue
        try:
            # Gates drive real CLI commands; their own JSON output is noise here.
            with redirect_stdout(io.StringIO()):
                detail = gate()
            results.append(GateResult(gate_id, title, True, detail))
        except Exception as exc:  # noqa: BLE001 -- a failing gate is reported, never raised
            detail = str(exc) or "".join(traceback.format_exception_only(type(exc), exc)).strip()
            results.append(GateResult(gate_id, title, False, detail))
    return {"passed": all(result.passed for result in results), "gates": [result.to_dict() for result in results]}
