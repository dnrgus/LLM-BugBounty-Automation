from __future__ import annotations

import json
from pathlib import Path

import httpx

from core.contract import SCHEMA_VERSIONS
from core.models import Finding, FindingStatus, Reproduction, Run, new_id, utc_now
from reporting.evidence import write_evidence_bundle
from reporting.integrity import build_run_manifest
from scope.policy import PolicyEngine
from source.audit import collect_source_items
from source.endpoints import EndpointSpec, build_endpoint_inventory, load_captured_requests
from storage.sqlite import SQLiteStore
from validation.auth_contexts import AuthContextSet, object_id_candidates
from validation.endpoint_validator import PlannedRequest, RequestValidationEvidence, validate_endpoint_request
from validation.finding_adapter import LIMITATIONS_BY_VALIDATOR_TYPE, finding_from_object_access
from validation.object_access_validator import ObjectAccessResult, fill_path_param, validate_object_access
from validation.planner import generate_validation_plans

# P4.5 WP-03 (v5.0 plan 5.3): the scan -> validate -> reproduce -> report
# CLI flow. `scan` writes one JSON artifact every later step reads, so
# each step can be re-run on its own without redoing static analysis.

SCAN_ARTIFACT_SCHEMA_VERSION = str(SCHEMA_VERSIONS["scan_artifact"])


def build_scan_artifact(
    source_root: Path | str, captured_requests: Path | str | None = None, max_files: int = 2000
) -> dict[str, object]:
    ingestion, items = collect_source_items(source_root, max_files=max_files)
    captured = load_captured_requests(captured_requests) if captured_requests else None
    inventory = build_endpoint_inventory(items, captured=captured)
    plans = generate_validation_plans(items)
    return {
        "schema_version": SCAN_ARTIFACT_SCHEMA_VERSION,
        "kind": "scan_artifact",
        "id": new_id("scan"),
        "created_at": utc_now(),
        "source_root": str(ingestion.root),
        "captured_requests": str(captured_requests) if captured_requests else None,
        "items": [item.to_dict() for item in items],
        "endpoint_inventory": [spec.to_dict() for spec in inventory],
        "object_id_candidates": {spec.id: object_id_candidates(spec) for spec in inventory},
        "validation_plans": [plan.to_dict() for plan in plans],
    }


def write_artifact(path: Path | str, artifact: dict[str, object]) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(artifact, indent=2, sort_keys=True), encoding="utf-8")
    return target


def load_scan_artifact(path: Path | str) -> dict[str, object]:
    artifact = json.loads(Path(path).read_text(encoding="utf-8"))
    if artifact.get("kind") != "scan_artifact":
        raise ValueError(f"{path} is not a scan artifact")
    if str(artifact.get("schema_version")) != SCAN_ARTIFACT_SCHEMA_VERSION:
        raise ValueError(f"unsupported scan artifact schema_version: {artifact.get('schema_version')!r}")
    return artifact


def _record(store: SQLiteStore, run_id: str, kind: str, name: str, payload: dict[str, object]):
    bundle = write_evidence_bundle(Path("evidence/raw"), Path("evidence/sanitized"), f"{run_id}_{name}.json", payload)
    return store.record_evidence(run_id, kind, bundle.sanitized_path, raw_path=bundle.raw_path)


def _fill_known_path_params(spec: EndpointSpec, auth_contexts: AuthContextSet | None) -> str | None:
    path = spec.path
    for param in spec.path_params:
        value = next(
            (a.owned_objects[param] for a in (auth_contexts.usable_accounts() if auth_contexts else []) if param in a.owned_objects),
            None,
        )
        if value is None:
            return None
        path = fill_path_param(path, param, value)
    return path


def _first_account_headers(auth_contexts: AuthContextSet | None) -> dict[str, str] | None:
    accounts = auth_contexts.usable_accounts() if auth_contexts else []
    return dict(accounts[0].context.headers) if accounts else None


def _object_access_needs_review(spec: EndpointSpec, reason: str, param: str | None) -> ObjectAccessResult:
    return ObjectAccessResult(spec.id, spec.method, param, None, None, "needs_review", reason)


async def run_validate(
    artifact: dict[str, object],
    base_url: str,
    policy: PolicyEngine,
    store: SQLiteStore,
    auth_contexts: AuthContextSet | None = None,
    key_fields: list[str] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, object]:
    """Runs every applicable safe validator over the artifact's endpoint
    inventory. Each request goes through the common gate (scope, then
    method policy); dry-run/review-required requests are recorded, not
    sent. Object access comparison runs only for read-only endpoints with
    a path object id, and without auth contexts it stops with a recorded
    needs_review reason instead of sending anything."""
    store.initialize()
    run = Run(target_id=base_url, policy_hash=policy.policy_hash, fingerprint=f"validate:{artifact['id']}")
    store.insert_run(run)

    specs = [EndpointSpec.from_dict(entry) for entry in artifact.get("endpoint_inventory", [])]  # type: ignore[union-attr]
    request_results: list[dict[str, object]] = []
    object_results: list[dict[str, object]] = []
    findings: list[Finding] = []

    for spec in specs:
        path = _fill_known_path_params(spec, auth_contexts)
        if path is None:
            # A path parameter with no tester-declared value: the request
            # is still planned (so state-changing methods reach the gate
            # and the record), but never sent to a guessed id.
            evidence = RequestValidationEvidence(
                base_url.rstrip("/") + spec.path, spec.method, spec.risk, "review_required",
                "path parameter value unknown; declare it via --auth-contexts owned_objects",
                planned_request=PlannedRequest(spec.method, base_url.rstrip("/") + spec.path, spec.body_format, spec.body_fields),
            )
        else:
            evidence = await validate_endpoint_request(
                base_url.rstrip("/") + path, spec.method, policy, body_format=spec.body_format,
                body_fields=spec.body_fields, example_body=spec.example_body,
                headers=_first_account_headers(auth_contexts), transport=transport,
            )
        stored = _record(store, run.id, "endpoint_request", f"{spec.id}_request", evidence.to_dict())
        request_results.append({"endpoint_id": spec.id, "evidence_id": stored.id, **evidence.to_dict()})

        path_ids = [c["name"] for c in object_id_candidates(spec) if c["location"] == "path"]
        if not path_ids or spec.risk != "read_only":
            continue
        if auth_contexts is None:
            result = _object_access_needs_review(spec, "no --auth-contexts supplied; comparison not attempted", path_ids[0])
        else:
            result = await validate_object_access(spec, base_url, auth_contexts, policy, key_fields=key_fields, transport=transport)
        stored = _record(store, run.id, "object_access", f"{spec.id}_object_access", result.to_dict())
        finding = finding_from_object_access(
            run.id, result, stored.id,
            replay={"endpoint_spec": spec.to_dict(), "base_url": base_url, "key_fields": list(key_fields or [])},
        )
        store.insert_finding(finding)
        findings.append(finding)
        object_results.append({"evidence_id": stored.id, "finding_id": finding.id, **result.to_dict()})

    by_status: dict[str, int] = {}
    for finding in findings:
        by_status[finding.status.value] = by_status.get(finding.status.value, 0) + 1
    return {
        "run_id": run.id,
        "artifact_id": artifact["id"],
        "base_url": base_url,
        "request_validations": request_results,
        "object_access_validations": object_results,
        "findings": [{"finding_id": f.id, "status": f.status.value, "title": f.title} for f in findings],
        "findings_by_status": by_status,
    }


def is_replayable_validation_finding(finding: Finding) -> bool:
    spec = finding.reproduction_spec
    return spec.get("type") == "validation" and spec.get("validator_type") == "object_access" and "endpoint_spec" in spec


async def reproduce_validation_finding(
    finding: Finding,
    policy: PolicyEngine,
    store: SQLiteStore,
    auth_contexts: AuthContextSet | None,
    attempts: int = 3,
    transport: httpx.AsyncBaseTransport | None = None,
    environment: dict[str, object] | None = None,
) -> dict[str, object]:
    """Re-runs the same object access comparison `attempts` times under
    the same conditions and stores attempts/successes/results. A success
    is an attempt reaching the finding's original verdict."""
    spec_data = finding.reproduction_spec
    spec = EndpointSpec.from_dict(spec_data["endpoint_spec"])
    base_url = str(spec_data["base_url"])
    key_fields = list(spec_data.get("key_fields", []))
    original = finding.validation_status or finding.status.value

    verdicts: list[str] = []
    results: list[dict[str, object]] = []
    for _ in range(max(1, attempts)):
        if auth_contexts is None:
            result = _object_access_needs_review(spec, "no --auth-contexts supplied; comparison not attempted", None)
        else:
            result = await validate_object_access(spec, base_url, auth_contexts, policy, key_fields=key_fields, transport=transport)
        verdicts.append(result.verdict)
        results.append(result.to_dict())

    successes = sum(1 for verdict in verdicts if verdict == original)
    if successes == len(verdicts):
        status = finding.status
    elif successes == 0:
        status = FindingStatus.REJECTED if original == "confirmed" else FindingStatus.NEEDS_REVIEW
    else:
        status = FindingStatus.UNSTABLE
    reproduction = Reproduction(finding_id=finding.id, attempts=len(verdicts), successes=successes, control_passed=True, status=status)
    store.insert_reproduction(reproduction)
    stored = _record(
        store, finding.run_id, "reproduction", f"{finding.id}_{reproduction.id}",
        {
            "finding_id": finding.id, "original_verdict": original, "verdicts": verdicts, "results": results,
            "environment": environment or {},
        },
    )
    return {
        "finding_id": finding.id,
        "original_status": finding.status.value,
        "reproduction": {
            "type": "validation",
            "validator_type": "object_access",
            "attempts": reproduction.attempts,
            "successes": successes,
            "success_rate": reproduction.success_rate,
            "verdicts": verdicts,
            "status": status.value,
            "evidence_id": stored.id,
        },
    }


# --- report --------------------------------------------------------------------

_STATUS_LABELS = {
    "confirmed": "확정됨",
    "needs_review": "검토 필요",
    "candidate": "후보",
    "rejected": "기각됨",
    "unstable": "불안정",
}


def write_validation_report(store: SQLiteStore, run_id: str, out_dir: Path | str) -> dict[str, object]:
    """One markdown + JSON report per finding of a `validate` run, plus
    an index. Every report carries status, the evidence path and SHA-256,
    reproduction history, reproduction steps, and limitations."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    evidence_by_id = {row["id"]: row for row in store.list_evidence(run_id)}
    # P4.7 WP-08: re-hash every evidence file now; a report never silently
    # cites evidence that changed after it was recorded.
    manifest = build_run_manifest(store, run_id)
    tampered = {entry.evidence_id for entry in manifest.entries if entry.tamper_detected}
    index: list[dict[str, object]] = []

    for finding in store.list_findings([run_id]):
        evidence = evidence_by_id.get(finding.evidence_ref)
        evidence_info = (
            {"id": evidence["id"], "path": evidence["path"], "sha256": evidence["sha256"], "tamper_detected": evidence["id"] in tampered}
            if evidence is not None
            else None
        )
        evidence_payload: dict[str, object] = {}
        if evidence is not None and evidence["id"] not in tampered:
            evidence_payload = json.loads(Path(evidence["path"]).read_text(encoding="utf-8"))
        reproductions = [
            {"attempts": row["attempts"], "successes": row["successes"], "status": row["status"]}
            for row in store.list_reproductions(finding.id)
        ]
        validator_type = str(finding.reproduction_spec.get("validator_type", finding.category))
        steps = [
            "python main.py scan --source <source> --artifact <artifact.json>",
            f"python main.py validate --artifact <artifact.json> --base-url {finding.reproduction_spec.get('base_url', '<url>')} "
            "--auth-contexts <auth.yaml>",
            f"python main.py reproduce {finding.id} --auth-contexts <auth.yaml>",
        ]
        payload = {
            "schema_version": SCHEMA_VERSIONS["validation_report"],
            "finding_id": finding.id,
            "title": finding.title,
            "status": finding.status.value,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "validator_type": validator_type,
            "reason": evidence_payload.get("reason"),
            "evidence": evidence_info,
            "reproductions": reproductions,
            "reproduction_steps": steps,
            "limitations": LIMITATIONS_BY_VALIDATOR_TYPE.get(validator_type),
        }
        (out / f"{finding.id}.json").write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        status_label = _STATUS_LABELS.get(finding.status.value, finding.status.value)
        lines = [
            f"# {finding.title}",
            "",
            f"- 상태: {status_label} ({finding.status.value})",
            f"- 심각도: {finding.severity}",
            f"- 신뢰도: {finding.confidence:.2f}",
            f"- 판정 근거: {payload['reason'] or '(없음)'}",
            f"- Evidence: `{evidence_info['path'] if evidence_info else '(없음)'}`",
            f"- Evidence SHA-256: `{evidence_info['sha256'] if evidence_info else '(없음)'}`",
            f"- Evidence 무결성: {'변조 감지됨 — 이 finding의 근거를 신뢰하지 말 것' if evidence_info and evidence_info['tamper_detected'] else '검증됨'}",
            "",
            "## 재현 기록",
            "",
            *([f"- {r['successes']}/{r['attempts']} -> {r['status']}" for r in reproductions] or ["- 아직 재현하지 않음"]),
            "",
            "## 재현 절차",
            "",
            *[f"{i}. `{step}`" for i, step in enumerate(steps, 1)],
            "",
            "## 제한사항",
            "",
            payload["limitations"] or "(없음)",
        ]
        (out / f"{finding.id}.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
        store.record_report(run_id, out / f"{finding.id}.md")
        index.append({"finding_id": finding.id, "status": finding.status.value, "report": str(out / f"{finding.id}.md")})

    by_status: dict[str, int] = {}
    for entry in index:
        by_status[str(entry["status"])] = by_status.get(str(entry["status"]), 0) + 1
    summary = {
        "run_id": run_id,
        "report_dir": str(out),
        "findings": index,
        "findings_by_status": by_status,
        "integrity": {"evidence_entries": len(manifest.entries), "tamper_detected": sorted(tampered)},
    }
    (out / "index.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return summary
