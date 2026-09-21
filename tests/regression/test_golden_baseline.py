"""U1: Regression Harness.

Locks down the *structural shape* of the v2 pipeline's key end-to-end
commands (not exact ids/hashes/timestamps, which are non-deterministic by
design -- see Reproducible principle) as the regression baseline for the
v3.0 Universal Architecture migration. Per the v3.0 doc's Migration Rules,
if one of these needs to change, that's a signal the migration touched
shared Core behavior, which should be a deliberate, reviewed decision --
not an accidental side effect of adding Discovery/Source/Pack layers.
"""

import asyncio
from pathlib import Path

from core.orchestrator import run_full_pipeline, run_sample_pipeline
from core.profile import load_profile
from judges.benchmark import load_benchmark_cases, run_benchmark
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from testcase.loader import load_testcases

FIXTURES = Path("tests/fixtures/tools")


def _policy() -> PolicyEngine:
    return PolicyEngine.from_yaml("config/scope.example.yaml")


def _testcases():
    return load_testcases("testcase/suites/basic.yaml")


def test_golden_judge_benchmark_has_zero_false_positives_and_negatives() -> None:
    cases = load_benchmark_cases("benchmarks/judge/baseline.json")
    result = run_benchmark(cases)
    assert result["metrics"]["false_positive"] == 0
    assert result["metrics"]["false_negative"] == 0
    assert result["metrics"]["precision"] == 1.0
    assert result["metrics"]["recall"] == 1.0


def test_golden_sample_run_against_fake_llm(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "golden_sample.sqlite")
    result = asyncio.run(run_sample_pipeline(_policy(), _testcases(), store, target_kind="fake-llm"))
    assert result["selected_testcases"] == ["LLM-PI-001", "LLM-SP-001"]
    assert result["finding_count"] == 1
    assert result["reproductions"]["confirmed"] == 1
    assert len(result["clusters"]) == 1
    assert result["clusters"][0]["category"] == "system_prompt_leak"


def test_golden_sample_run_against_fake_rag(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "golden_rag.sqlite")
    result = asyncio.run(run_sample_pipeline(_policy(), _testcases(), store, target_kind="fake-rag"))
    assert result["selected_testcases"] == ["LLM-PI-001", "LLM-SP-001", "LLM-RAG-001", "LLM-RAG-002"]
    assert result["finding_count"] == 1
    assert result["clusters"][0]["category"] == "indirect_injection"


def test_golden_full_scan_shape_is_stable(tmp_path: Path) -> None:
    profile = load_profile("full", "config/pipeline.yaml")
    store = SQLiteStore(tmp_path / "golden_full.sqlite")
    result = asyncio.run(
        run_full_pipeline(
            _policy(),
            _testcases(),
            store,
            profile,
            recon_inputs={
                "subfinder": FIXTURES / "subfinder-results.jsonl",
                "httpx": FIXTURES / "httpx-results.jsonl",
                "katana": FIXTURES / "katana-results.jsonl",
                "ffuf": FIXTURES / "ffuf-results.json",
            },
            pyrit_input=FIXTURES / "pyrit-results.json",
            external_inputs={
                "nuclei": FIXTURES / "nuclei-results.jsonl",
                "dalfox": FIXTURES / "dalfox-results.json",
                "trufflehog": FIXTURES / "trufflehog-results.jsonl",
            },
        )
    )
    assert result["profile"] == "full"
    assert result["stages"] == ["recon", "scan", "adaptive", "external_scan"]
    assert result["recon"]["assets"]["total"] == 3
    assert result["recon"]["endpoints"]["total"] == 7
    assert set(result["scan"].keys()) == {"fake-llm", "fake-agent", "fake-rag"}
    assert result["adaptive"]["pyrit_seed_results"] == 1
    assert result["external_scan"]["nuclei"]["count"] == 2
    assert result["external_scan"]["dalfox"]["count"] == 1
    assert result["external_scan"]["trufflehog"]["count"] == 2
    assert result["finding_count"] == 5

    categories = sorted(cluster["category"] for cluster in result["combined_clusters"])
    assert categories == ["indirect_injection", "system_prompt_leak"]
    sp_cluster = next(c for c in result["combined_clusters"] if c["category"] == "system_prompt_leak")
    assert sp_cluster["count"] == 4
