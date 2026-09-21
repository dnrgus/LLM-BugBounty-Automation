from __future__ import annotations

from pathlib import Path

from core.fingerprint import build_environment_fingerprint
from core.models import Finding, FindingStatus, Judgement, Run, Trace
from executor.runner import Executor
from judges.ensemble import JudgeEnsemble
from reporting.reporter import write_markdown_report
from reporting.sanitizer import sanitize_artifact
from scope.policy import PolicyEngine
from storage.artifacts import write_json_artifact
from storage.sqlite import SQLiteStore
from targets.fake import FakeLLMTarget
from testcase.schema import Testcase


async def run_sample_pipeline(
    policy: PolicyEngine,
    testcases: list[Testcase],
    store: SQLiteStore,
) -> dict[str, object]:
    target = FakeLLMTarget()
    capabilities = await target.capabilities()
    selected = [case for case in testcases if capabilities.supports(case.requires)]
    fingerprint = build_environment_fingerprint(
        {
            "target_build": "fake",
            "model_provider": "fake",
            "model_name": "fake-llm",
            "model_version": "offline",
            "temperature": 0,
            "seed": 0,
            "system_prompt_hash": "none",
            "tool_schema_hash": "none",
            "rag_corpus_hash": "none",
            "testcase_version": "basic",
            "policy_hash": policy.policy_hash,
        }
    )
    run = Run(
        target_id="fake-llm",
        policy_hash=policy.policy_hash,
        fingerprint=fingerprint["fingerprint"],
    )
    store.initialize()
    store.insert_run(run)

    executor = Executor(policy=policy, target=target, store=store)
    judges = JudgeEnsemble.default()
    findings: list[Finding] = []
    reports: list[str] = []

    for case in selected:
        trace = Trace(run_id=run.id, testcase_id=case.id)
        store.insert_trace(trace)
        response = await executor.execute(
            run=run,
            trace=trace,
            testcase=case,
            url="https://ai.example.com/api/chat",
        )
        judgement = judges.judge(run.id, case, response.text)
        store.insert_judgement(judgement)
        raw_path = write_json_artifact(
            Path("evidence/raw"),
            f"{run.id}_{case.id}.json",
            {"prompt": response.prompt, "response": response.text, "trace_id": trace.id},
        )
        sanitized = sanitize_artifact(raw_path, Path("evidence/sanitized"))
        evidence = store.record_evidence(run.id, "llm_response", sanitized)
        if judgement.passed:
            finding = Finding(
                run_id=run.id,
                testcase_id=case.id,
                title=case.name,
                category=case.category,
                status=FindingStatus.CANDIDATE,
                confidence=judgement.score,
                severity=case.severity.get("base", "medium"),
                evidence_ref=evidence.id,
            )
            store.insert_finding(finding)
            findings.append(finding)
            report = write_markdown_report(Path("reports/shareable"), run, case, finding, judgement, sanitized)
            store.record_report(run.id, report)
            reports.append(str(report))

    return {
        "run_id": run.id,
        "selected_testcases": [case.id for case in selected],
        "finding_count": len(findings),
        "reports": reports,
        "fingerprint": run.fingerprint,
    }

