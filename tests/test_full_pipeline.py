import asyncio
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

from core.orchestrator import run_full_pipeline, run_sample_pipeline
from core.profile import load_profile
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from testcase.loader import load_testcases

FIXTURES = Path("tests/fixtures/tools")


def _policy() -> PolicyEngine:
    return PolicyEngine.from_yaml("config/scope.example.yaml")


def _testcases():
    return load_testcases("testcase/suites/basic.yaml")


def test_profile_budget_zero_requests_stops_before_any_testcase_runs(tmp_path: Path) -> None:
    profile = replace(load_profile("quick", "config/pipeline.yaml"), budget_max_requests=0)
    store = SQLiteStore(tmp_path / "budget.sqlite")
    result = asyncio.run(run_sample_pipeline(_policy(), _testcases(), store, target_kind="fake-llm", profile=profile))
    assert len(result["selected_testcases"]) > 0
    assert result["executed_testcases"] == []
    assert result["budget"]["stop_reason"] == "budget_exhausted:requests"


def test_profile_budget_commits_usage_after_executing_a_testcase(tmp_path: Path) -> None:
    profile = replace(load_profile("quick", "config/pipeline.yaml"), budget_max_requests=1, testcase_limit=1)
    store = SQLiteStore(tmp_path / "budget_commit.sqlite")
    result = asyncio.run(run_sample_pipeline(_policy(), _testcases(), store, target_kind="fake-llm", profile=profile))
    assert result["executed_testcases"] == ["LLM-PI-001"]
    assert result["budget"]["requests_used"] == 1


async def _run_sample_pipeline_with_failing_target(monkeypatch, store, profile=None):
    import core.orchestrator as orchestrator_module
    from targets.errors import TargetConnectionError
    from targets.fake import FakeLLMTarget

    class AlwaysFailingTarget(FakeLLMTarget):
        async def send(self, prompt, session=None):
            raise TargetConnectionError("simulated outage")

    monkeypatch.setattr(orchestrator_module, "create_target", lambda kind, config=None: AlwaysFailingTarget())
    return await run_sample_pipeline(_policy(), _testcases(), store, target_kind="fake-llm", profile=profile)


def test_repeated_target_errors_stop_the_run_gracefully_instead_of_crashing(tmp_path, monkeypatch) -> None:
    store = SQLiteStore(tmp_path / "failing.sqlite")
    result = asyncio.run(_run_sample_pipeline_with_failing_target(monkeypatch, store))
    # 2 testcases are selected against fake-llm (chat-only, no rag/tools); every
    # send() raises, so the loop must stop gracefully rather than propagate.
    assert result["finding_count"] == 0
    assert len(result["executed_testcases"]) == 0


def test_profile_testcase_limit_slices_selected_testcases(tmp_path: Path) -> None:
    profile = replace(load_profile("quick", "config/pipeline.yaml"), testcase_limit=1)
    store = SQLiteStore(tmp_path / "quick.sqlite")
    result = asyncio.run(run_sample_pipeline(_policy(), _testcases(), store, target_kind="fake-llm", profile=profile))
    assert result["selected_testcases"] == ["LLM-PI-001"]


def test_profile_mutation_disabled_skips_mutation_even_when_testcase_enables_it(tmp_path: Path) -> None:
    profile = load_profile("quick", "config/pipeline.yaml")
    assert profile.mutation_enabled is False
    cases = [
        replace(case, mutation={"enabled": True}) if case.id == "LLM-PI-001" else case for case in _testcases()
    ]
    store = SQLiteStore(tmp_path / "quick_mut.sqlite")
    asyncio.run(run_sample_pipeline(_policy(), cases, store, target_kind="fake-llm", profile=profile))
    with store.connect() as conn:
        count = conn.execute("select count(*) as n from mutations").fetchone()["n"]
    assert count == 0


def test_full_pipeline_web_profile_only_runs_recon_and_external_scan(tmp_path: Path) -> None:
    profile = load_profile("web", "config/pipeline.yaml")
    store = SQLiteStore(tmp_path / "web.sqlite")
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
            external_inputs={
                "nuclei": FIXTURES / "nuclei-results.jsonl",
                "dalfox": FIXTURES / "dalfox-results.json",
                "trufflehog": FIXTURES / "trufflehog-results.jsonl",
            },
        )
    )
    assert result["recon"]["assets"]["total"] == 3
    assert result["external_scan"]["nuclei"]["count"] == 2
    assert result["external_scan"]["trufflehog"]["count"] == 2
    assert "scan" in result and result["scan"] == {}
    assert "adaptive" not in result
    assert result["finding_count"] == 0


def test_full_pipeline_combines_findings_across_scan_and_adaptive_into_shared_cluster(tmp_path: Path) -> None:
    profile = load_profile("full", "config/pipeline.yaml")
    store = SQLiteStore(tmp_path / "full.sqlite")
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
    assert set(result["scan"].keys()) == {"fake-llm", "fake-agent", "fake-rag"}
    assert result["adaptive"]["pyrit_seed_results"] == 1
    sp_leak_cluster = next(c for c in result["combined_clusters"] if c["category"] == "system_prompt_leak")
    # 1 confirmed finding from the plain scan stage + 3 PyRIT adaptive mutation variants,
    # all sharing the same root_cause_key for the LLM-SP-001 seed testcase.
    assert sp_leak_cluster["count"] == 4
    assert sp_leak_cluster["root_cause_key"] == next(
        c["root_cause_key"] for c in result["adaptive"]["clusters"] if c["category"] == "system_prompt_leak"
    )
    # REJECTED findings (e.g. LLM-PI-001 under fake-rag/fake-agent) must never pollute the
    # combined cluster -- only CONFIRMED/UNSTABLE findings count.
    assert result["finding_count"] == sum(c["count"] for c in result["combined_clusters"])
    with store.connect() as conn:
        rejected = conn.execute("select count(*) as n from findings where status = 'rejected'").fetchone()["n"]
    assert rejected > 0


def test_scan_cli_full_profile_runs_end_to_end(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "scan",
            "--profile",
            "full",
            "--db",
            str(tmp_path / "scan_full.sqlite"),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(result.stdout)
    assert payload["profile"] == "full"
    assert payload["stages"] == ["recon", "scan", "adaptive", "external_scan"]
    assert payload["recon"]["assets"]["total"] == 3
    assert set(payload["scan"].keys()) == {"fake-llm", "fake-agent", "fake-rag"}
    assert payload["adaptive"]["pyrit_seed_results"] == 1
    assert payload["external_scan"]["nuclei"]["count"] == 2
    assert payload["finding_count"] > 0
    assert any(path.endswith("_root_cause_clusters.json") for path in payload["reports"])


def test_scan_cli_web_profile_skips_llm_scan(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "scan",
            "--profile",
            "web",
            "--db",
            str(tmp_path / "scan_web.sqlite"),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(result.stdout)
    assert payload["scan"] == {}
    assert "adaptive" not in payload
    assert payload["external_scan"]["dalfox"]["count"] == 1
