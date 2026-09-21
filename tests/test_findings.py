from pathlib import Path

from core.models import Finding, FindingStatus, Run
from findings.dedup import base_testcase_id, cluster_findings, root_cause_key
from findings.report import write_cluster_report


def _finding(testcase_id: str, title: str, category: str = "system_prompt_leak", severity: str = "high", confidence: float = 1.0) -> Finding:
    return Finding(
        run_id="run_1",
        testcase_id=testcase_id,
        title=title,
        category=category,
        status=FindingStatus.CONFIRMED,
        confidence=confidence,
        severity=severity,
        evidence_ref="evidence_1",
    )


def test_base_testcase_id_strips_mutation_suffix() -> None:
    assert base_testcase_id("LLM-SP-001::mutation_abc123") == "LLM-SP-001"
    assert base_testcase_id("LLM-SP-001") == "LLM-SP-001"


def test_root_cause_key_stable_across_mutation_variants_and_differs_by_category() -> None:
    seed_key = root_cause_key("system_prompt_leak", "LLM-SP-001")
    mutation_key = root_cause_key("system_prompt_leak", "LLM-SP-001::mutation_abc123")
    assert seed_key == mutation_key
    assert root_cause_key("tool_abuse", "LLM-SP-001") != seed_key


def test_cluster_findings_merges_mutation_variants_of_same_seed_testcase() -> None:
    findings = [
        _finding("LLM-SP-001::mutation_a", "Canary System Prompt Leak"),
        _finding("LLM-SP-001::mutation_b", "Canary System Prompt Leak"),
        _finding("LLM-SP-001::mutation_c", "Canary System Prompt Leak"),
    ]
    clusters = cluster_findings(findings)
    assert len(clusters) == 1
    assert clusters[0].count == 3
    assert sorted(clusters[0].testcase_ids) == [
        "LLM-SP-001::mutation_a",
        "LLM-SP-001::mutation_b",
        "LLM-SP-001::mutation_c",
    ]


def test_cluster_findings_merges_similar_titles_across_different_testcases() -> None:
    findings = [
        _finding("LLM-SP-001", "Canary System Prompt Leak"),
        _finding("LLM-SP-002", "Canary System Prompt Leak Confirmed"),
    ]
    clusters = cluster_findings(findings)
    assert len(clusters) == 1
    assert clusters[0].count == 2


def test_cluster_findings_keeps_distinct_categories_separate() -> None:
    findings = [
        _finding("LLM-SP-001", "Canary System Prompt Leak", category="system_prompt_leak"),
        _finding("LLM-TOOL-001", "Unauthorized Tool Invocation", category="tool_abuse"),
    ]
    clusters = cluster_findings(findings)
    assert len(clusters) == 2


def test_cluster_representative_picks_highest_severity_and_confidence() -> None:
    findings = [
        _finding("LLM-SP-001::mutation_a", "Canary System Prompt Leak", severity="medium", confidence=0.5),
        _finding("LLM-SP-001::mutation_b", "Canary System Prompt Leak", severity="high", confidence=1.0),
    ]
    clusters = cluster_findings(findings)
    assert clusters[0].severity == "high"
    assert clusters[0].max_confidence == 1.0


def test_root_cause_key_links_the_same_seed_testcase_across_separate_runs() -> None:
    run_a_finding = _finding("LLM-SP-001", "Canary System Prompt Leak")
    run_b_finding = _finding("LLM-SP-001::mutation_xyz", "Canary System Prompt Leak")
    key_a = cluster_findings([run_a_finding])[0].root_cause_key
    key_b = cluster_findings([run_b_finding])[0].root_cause_key
    assert key_a == key_b


def test_write_cluster_report_writes_expected_shape(tmp_path: Path) -> None:
    findings = [
        _finding("LLM-SP-001::mutation_a", "Canary System Prompt Leak"),
        _finding("LLM-SP-001::mutation_b", "Canary System Prompt Leak"),
    ]
    clusters = cluster_findings(findings)
    run = Run(target_id="target_1", policy_hash="hash", fingerprint="fp")
    path = write_cluster_report(tmp_path, run, clusters)
    assert path.exists()
    import json

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["run_id"] == run.id
    assert payload["cluster_count"] == 1
    assert payload["finding_count"] == 2
