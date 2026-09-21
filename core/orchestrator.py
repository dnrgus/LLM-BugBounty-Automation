from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from attacks.mutation import MutationEngine
from core.fingerprint import build_environment_fingerprint
from core.models import (
    Finding,
    FindingStatus,
    PromptRecord,
    RequestRecord,
    ResponseRecord,
    Run,
    StoredTestcase,
    Target,
    Trace,
)
from executor.runner import Executor
from judges.ensemble import JudgeEnsemble
from reporting.evidence import write_evidence_bundle
from reporting.reporter import write_json_report, write_markdown_report
from reproduction.reproducer import Reproducer
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from targets.factory import create_target
from testcase.coverage import build_coverage_matrix, coverage_summary
from testcase.selector import select_executable_testcases
from testcase.schema import Testcase


async def run_sample_pipeline(
    policy: PolicyEngine,
    testcases: list[Testcase],
    store: SQLiteStore,
    target_kind: str = "fake-llm",
) -> dict[str, object]:
    target = create_target(target_kind)
    capabilities = await target.capabilities()
    target_metadata = await target.metadata()
    selected = select_executable_testcases(testcases, capabilities, policy)
    fingerprint = build_environment_fingerprint(
        {
            "target_build": target_metadata.kind,
            "model_provider": target_metadata.provider,
            "model_name": target_metadata.name,
            "model_version": target_metadata.version,
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
        target_id=target_metadata.id,
        policy_hash=policy.policy_hash,
        fingerprint=fingerprint["fingerprint"],
    )
    store.initialize()
    store.insert_target(
        Target(
            id=target_metadata.id,
            kind=target_metadata.kind,
            base_url=target_metadata.base_url,
            capabilities=capabilities.to_dict(),
            metadata=asdict(target_metadata),
        )
    )
    store.insert_run(run)

    executor = Executor(policy=policy, target=target, store=store, target_id=target_metadata.id)
    judges = JudgeEnsemble.default()
    reproducer = Reproducer(target=target, judges=judges)
    mutation_engine = MutationEngine()
    findings: list[Finding] = []
    reports: list[str] = []
    reproduction_summary = {"confirmed": 0, "unstable": 0, "rejected": 0}

    for case in selected:
        store.insert_testcase(
            StoredTestcase(
                id=case.id,
                name=case.name,
                category=case.category,
                content_hash=case.content_hash,
                frameworks=case.frameworks,
            )
        )
        prompt = PromptRecord(testcase_id=case.id, prompt_hash=case.content_hash, text=case.prompt)
        store.insert_prompt(prompt)
        if case.mutation.get("enabled", False):
            for mutation in mutation_engine.mutate(case):
                store.insert_mutation(mutation.to_record())
        trace = Trace(run_id=run.id, testcase_id=case.id)
        store.insert_trace(trace)
        request = RequestRecord(
            run_id=run.id,
            trace_id=trace.id,
            testcase_id=case.id,
            prompt_hash=case.content_hash,
            metadata={"target_id": target_metadata.id},
        )
        store.insert_request(request)
        response = await executor.execute(
            run=run,
            trace=trace,
            testcase=case,
            url=target_metadata.base_url,
        )
        store.insert_response(
            ResponseRecord(
                request_id=request.id,
                trace_id=trace.id,
                status_code=200,
                token_count=len(response.text.split()),
                metadata=response.metadata,
            )
        )
        judgement = judges.judge(run.id, case, response.text)
        store.insert_judgement(judgement)
        evidence_bundle = write_evidence_bundle(
            Path("evidence/raw"),
            Path("evidence/sanitized"),
            f"{run.id}_{case.id}.json",
            {
                "prompt": response.prompt,
                "response": response.text,
                "trace_id": trace.id,
                "judgement": judgement.reason,
                "environment_fingerprint": run.fingerprint,
            },
        )
        evidence = store.record_evidence(run.id, "llm_response", evidence_bundle.sanitized_path)
        if judgement.passed:
            reproduction = await reproducer.reproduce(case, session_prefix=f"{run.id}:{case.id}")
            finding = Finding(
                run_id=run.id,
                testcase_id=case.id,
                title=case.name,
                category=case.category,
                status=reproduction.status,
                confidence=judgement.score,
                severity=case.severity.get("base", "medium"),
                evidence_ref=evidence.id,
            )
            store.insert_finding(finding)
            store.insert_reproduction(reproduction.to_record(finding.id))
            reproduction_summary[finding.status.value] = reproduction_summary.get(finding.status.value, 0) + 1
            if finding.status in {FindingStatus.CONFIRMED, FindingStatus.UNSTABLE}:
                findings.append(finding)
                metadata = evidence_bundle.to_dict()
                report = write_markdown_report(
                    Path("reports/shareable"),
                    run,
                    case,
                    finding,
                    judgement,
                    evidence_bundle.sanitized_path,
                    reproduction=reproduction,
                    evidence_metadata=metadata,
                )
                json_report = write_json_report(
                    Path("reports/shareable"),
                    run,
                    case,
                    finding,
                    judgement,
                    metadata,
                    reproduction=reproduction,
                )
                store.record_report(run.id, report)
                store.record_report(run.id, json_report)
                reports.extend([str(report), str(json_report)])

    return {
        "run_id": run.id,
        "selected_testcases": [case.id for case in selected],
        "finding_count": len(findings),
        "reports": reports,
        "fingerprint": run.fingerprint,
        "target": target_metadata.id,
        "coverage": coverage_summary(
            build_coverage_matrix(testcases, capabilities, {case.id for case in selected})
        ),
        "reproductions": reproduction_summary,
    }
