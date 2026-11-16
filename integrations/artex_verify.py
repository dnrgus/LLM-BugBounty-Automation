"""Replay a narrowly supported ARTEX HTTP candidate through the common policy gate.

The input contract is artex-verify/v1. Only a read-only response differential
with an explicit control and marker is currently supported. Other classes
return unavailable instead of being promoted to confirmed.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from reporting.evidence import write_evidence_bundle
from scope.policy import PolicyEngine
from validation.auth_contexts import load_auth_contexts


def _result(status: str, reason: str, **kwargs: object) -> dict:
    return {"schema": "artex-verify/v1", "status": status, "reason": reason, **kwargs}


async def verify(candidate: dict, policy: PolicyEngine, output: Path,
                 auth_contexts: Path | None = None,
                 transport: httpx.AsyncBaseTransport | None = None) -> dict:
    required = ("target_url", "method", "auth_context", "prerequisites",
                "success_criteria", "observed_evidence", "vulnerability_type")
    missing = [key for key in required if key not in candidate]
    if missing:
        return _result("unavailable", "missing fields: " + ", ".join(missing))
    if candidate["vulnerability_type"] != "response_differential":
        return _result("unavailable", "unsupported vulnerability type")
    if candidate["method"] != "GET":
        return _result("unavailable", "only GET replay is supported")
    criteria = candidate["success_criteria"]
    if not isinstance(criteria, dict) or criteria.get("type") != "body_contains":
        return _result("unavailable", "unsupported success criterion")
    marker = criteria.get("value")
    control_url = criteria.get("control_url")
    target_url = candidate["target_url"]
    if not isinstance(marker, str) or not marker or not isinstance(control_url, str):
        return _result("unavailable", "marker and control_url are required")
    if not isinstance(candidate["prerequisites"], list) or not isinstance(candidate["observed_evidence"], dict) or not candidate["observed_evidence"]:
        return _result("unavailable", "prerequisites and observed evidence are required")
    if candidate["prerequisites"]:
        return _result("unavailable", "prerequisite steps cannot be replayed automatically")
    if not isinstance(target_url, str) or urlsplit(target_url).scheme not in {"http", "https"}:
        return _result("unavailable", "invalid target URL")

    headers: dict[str, str] = {}
    context_id = candidate["auth_context"]
    if context_id != "anonymous":
        if auth_contexts is None:
            return _result("unavailable", "auth contexts file required")
        contexts = load_auth_contexts(auth_contexts)
        account = next((item for item in contexts.accounts if item.context.id == context_id), None)
        if account is None or not account.usable:
            return _result("unavailable", "authentication context unavailable")
        headers = dict(account.context.headers)

    # Check both URLs before sending either request. Each request consumes the
    # same policy budget used elsewhere in this repository.
    for url in (target_url, control_url):
        decision = policy.validate_request(url, "GET")
        if not decision.allowed:
            return _result("unavailable", "policy denied request: " + decision.reason)

    observations: list[dict] = []
    async with httpx.AsyncClient(timeout=10, follow_redirects=False, transport=transport) as client:
        for role, url in (("control", control_url), ("proof_1", target_url), ("proof_2", target_url)):
            budget = policy.consume_request_budget()
            if not budget.allowed:
                return _result("unavailable", budget.reason, observations=observations)
            try:
                response = await client.get(url, headers=headers)
            except httpx.HTTPError as exc:
                observations.append({"role": role, "url": url, "error": type(exc).__name__})
                continue
            observations.append({
                "role": role, "url": url, "status_code": response.status_code,
                "body_sha256": hashlib.sha256(response.content).hexdigest(),
                "marker_present": marker in response.text,
            })

    control = observations[0]
    proofs = observations[1:]
    if any(item.get("status_code") in {401, 403} for item in observations):
        status, reason = "unavailable", "authentication failed or access denied"
    elif "error" in control or any("error" in item for item in proofs):
        status, reason = "unstable", "one or more replay requests failed"
    elif control["marker_present"]:
        status, reason = "rejected", "control response also contains marker"
    else:
        passes = sum(bool(item["marker_present"]) for item in proofs)
        status = "confirmed" if passes == 2 else "unstable" if passes == 1 else "rejected"
        reason = f"marker matched in {passes}/2 proof replays and 0/1 control"

    bundle = write_evidence_bundle(output / "evidence" / "raw", output / "evidence" / "sanitized",
                                   "verification.json", {
                                       "candidate": {k: v for k, v in candidate.items() if k != "observed_evidence"},
                                       "observed_evidence": candidate["observed_evidence"],
                                       "observations": observations, "status": status, "reason": reason,
                                       "policy_hash": policy.policy_hash,
                                   })
    report_path = output / "report.md"
    report_path.write_text(
        "# ARTEX candidate verification\n\n"
        f"- Target: {target_url}\n- Status: {status}\n- Reason: {reason}\n"
        f"- Evidence SHA-256: {bundle.sanitized_sha256}\n\n"
        "## Replay observations\n\n```json\n"
        + json.dumps(observations, ensure_ascii=False, indent=2) + "\n```\n",
        encoding="utf-8",
    )
    return _result(status, reason, observations=observations,
                   target_url=target_url, vulnerability_type=candidate["vulnerability_type"],
                   candidate_id=str(candidate.get("candidate_id", "")),
                   title=str(candidate.get("title", "Response differential")),
                   results_dir=str(output.resolve()),
                   evidence={"path": str(bundle.sanitized_path), "sha256": bundle.sanitized_sha256},
                   report_path=str(report_path))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify an ARTEX candidate")
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--scope", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--auth-contexts", type=Path)
    args = parser.parse_args(argv)
    try:
        candidate = json.loads(args.candidate.read_text(encoding="utf-8"))
        result = asyncio.run(verify(candidate, PolicyEngine.from_yaml(args.scope), args.output,
                                    args.auth_contexts))
    except (OSError, ValueError, TypeError) as exc:
        result = _result("unavailable", type(exc).__name__ + ": " + str(exc))
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["status"] != "unavailable" else 1


if __name__ == "__main__":
    raise SystemExit(main())
