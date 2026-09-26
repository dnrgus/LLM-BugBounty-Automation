import asyncio
from pathlib import Path
from unittest.mock import patch

from core.tool_doctor import ToolStatus
from packs.registry import AttackPack
from packs.runner import run_selected_packs
from packs.selector import PackSelection
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from testcase.loader import load_testcases
from tools.runner import ExternalTool

_TESTCASES = load_testcases("testcase/suites/basic.yaml")


def _policy() -> PolicyEngine:
    # matches the fake targets' base_url (ai.example.com), same as
    # tests/test_reproducer.py's convention
    engine = PolicyEngine.from_yaml("config/scope.example.yaml")
    engine.config["testing"]["tool_abuse"] = True
    return engine


def _llm_core_pack() -> AttackPack:
    return AttackPack(
        id="llm_core",
        name="LLM Core Attack Suite",
        applies_to=("llm",),
        testing_categories=("prompt_injection", "system_prompt_leak"),
        estimated_request_cost=20,
        tool_ids=("testcase_suite",),
    )


def _secret_scan_pack() -> AttackPack:
    return AttackPack(
        id="secret_scan",
        name="Secret Exposure Scan",
        applies_to=("web",),
        testing_categories=("automated_scanning",),
        estimated_request_cost=10,
        tool_ids=("trufflehog",),
    )


def _unselected(pack: AttackPack) -> PackSelection:
    return PackSelection(pack, False, "does not apply to this target's classified capabilities")


def test_run_selected_packs_skips_unselected_packs(tmp_path) -> None:
    selections = [_unselected(_llm_core_pack())]
    store = SQLiteStore(tmp_path / "runner.sqlite")
    results = asyncio.run(run_selected_packs(selections, _TESTCASES, _policy(), store))
    assert results == []


def test_run_selected_packs_runs_testcase_suite_pack_against_a_target(tmp_path) -> None:
    selections = [PackSelection(_llm_core_pack(), True, "selected")]
    store = SQLiteStore(tmp_path / "runner.sqlite")

    results = asyncio.run(
        run_selected_packs(selections, _TESTCASES, _policy(), store, target_kind="fake-llm")
    )

    assert len(results) == 1
    result = results[0]
    assert result.tool_id == "testcase_suite"
    assert result.status == "ran"
    assert result.summary is not None
    selected_ids = result.summary["selected_testcases"]
    assert all(
        case.id in selected_ids
        for case in _TESTCASES
        if case.category in {"prompt_injection", "system_prompt_leak"}
    )
    # categories outside the pack must not leak into the filtered run
    assert not any(
        case.id in selected_ids for case in _TESTCASES if case.category not in {"prompt_injection", "system_prompt_leak"}
    )


def test_run_selected_packs_unions_categories_across_multiple_testcase_suite_packs(tmp_path) -> None:
    rag_pack = AttackPack(
        id="rag_injection", name="RAG Suite", applies_to=("rag",),
        testing_categories=("indirect_injection",), estimated_request_cost=15, tool_ids=("testcase_suite",),
    )
    selections = [
        PackSelection(_llm_core_pack(), True, "selected"),
        PackSelection(rag_pack, True, "selected"),
    ]
    store = SQLiteStore(tmp_path / "runner.sqlite")

    results = asyncio.run(
        run_selected_packs(selections, _TESTCASES, _policy(), store, target_kind="fake-rag")
    )

    # both testcase_suite packs collapse into a single pipeline run
    assert len(results) == 1
    assert "indirect_injection" in results[0].detail


def test_run_selected_packs_reports_no_target_when_none_supplied(tmp_path) -> None:
    selections = [PackSelection(_llm_core_pack(), True, "selected")]
    store = SQLiteStore(tmp_path / "runner.sqlite")

    results = asyncio.run(run_selected_packs(selections, _TESTCASES, _policy(), store))

    assert len(results) == 1
    assert results[0].status == "skipped_no_target"


def test_run_selected_packs_external_tool_not_installed(tmp_path) -> None:
    selections = [PackSelection(_secret_scan_pack(), True, "selected")]
    store = SQLiteStore(tmp_path / "runner.sqlite")

    def fake_checker(name: str) -> ToolStatus:
        return ToolStatus(name=name, available=False, path=None, version=None, status="warn")

    results = asyncio.run(
        run_selected_packs(selections, _TESTCASES, _policy(), store, tool_checker=fake_checker)
    )

    assert len(results) == 1
    assert results[0].status == "skipped_tool_not_installed"
    assert results[0].tool_id == "trufflehog"


def test_run_selected_packs_external_tool_installed_but_no_results_file(tmp_path) -> None:
    selections = [PackSelection(_secret_scan_pack(), True, "selected")]
    store = SQLiteStore(tmp_path / "runner.sqlite")

    def fake_checker(name: str) -> ToolStatus:
        return ToolStatus(name=name, available=True, path=f"/usr/bin/{name}", version="1.0", status="ok")

    results = asyncio.run(
        run_selected_packs(selections, _TESTCASES, _policy(), store, tool_checker=fake_checker)
    )

    assert len(results) == 1
    assert results[0].status == "skipped_no_results_file"


def test_run_selected_packs_external_tool_parses_supplied_results_file(tmp_path) -> None:
    selections = [PackSelection(_secret_scan_pack(), True, "selected")]
    store = SQLiteStore(tmp_path / "runner.sqlite")

    results = asyncio.run(
        run_selected_packs(
            selections, _TESTCASES, _policy(), store,
            external_scan_inputs={"trufflehog": "tests/fixtures/tools/trufflehog-results.jsonl"},
        )
    )

    assert len(results) == 1
    result = results[0]
    assert result.status == "ran"
    assert result.summary["count"] > 0


def test_run_selected_packs_multiple_external_tool_packs_reported_separately(tmp_path) -> None:
    nuclei_pack = AttackPack(
        id="web_scan", name="Web Vulnerability Scan", applies_to=("web",),
        testing_categories=("automated_scanning",), estimated_request_cost=50, tool_ids=("nuclei",),
    )
    selections = [
        PackSelection(nuclei_pack, True, "selected"),
        PackSelection(_secret_scan_pack(), True, "selected"),
    ]
    store = SQLiteStore(tmp_path / "runner.sqlite")

    results = asyncio.run(
        run_selected_packs(
            selections, _TESTCASES, _policy(), store,
            external_scan_inputs={
                "nuclei": "tests/fixtures/tools/nuclei-results.jsonl",
                "trufflehog": "tests/fixtures/tools/trufflehog-results.jsonl",
            },
        )
    )

    assert {r.tool_id for r in results} == {"nuclei", "trufflehog"}
    assert all(r.status == "ran" for r in results)


def test_pack_run_result_to_dict_is_json_serializable(tmp_path) -> None:
    import json

    selections = [PackSelection(_llm_core_pack(), True, "selected")]
    store = SQLiteStore(tmp_path / "runner.sqlite")
    results = asyncio.run(
        run_selected_packs(selections, _TESTCASES, _policy(), store, target_kind="fake-llm")
    )
    json.dumps([r.to_dict() for r in results])


def _fixture_nuclei_binary(tmp_path: Path) -> Path:
    script = tmp_path / "fixture-nuclei"
    script.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then echo "fixture-nuclei 1.0.0"; exit 0; fi\n'
        'echo \'{"template-id": "fixture", "info": {"name": "Fixture", "severity": "high"}, '
        '"matched-at": "https://ai.example.com/api/"}\'\n'
        "exit 0\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def test_run_selected_packs_runs_nuclei_live_when_installed_and_a_live_target_url_is_given(tmp_path) -> None:
    # P3.1-3: installed + no results file + a live_target_url -> actually
    # execute (tools/runner.py), instead of only reporting a skip.
    web_scan_pack = AttackPack(
        id="web_scan", name="Web Vulnerability Scan", applies_to=("web",),
        testing_categories=("automated_scanning",), estimated_request_cost=50, tool_ids=("nuclei",),
    )
    selections = [PackSelection(web_scan_pack, True, "selected")]
    store = SQLiteStore(tmp_path / "runner.sqlite")

    def fake_checker(name: str) -> ToolStatus:
        return ToolStatus(name=name, available=True, path=f"/usr/bin/{name}", version=None, status="ok")

    fixture_binary = _fixture_nuclei_binary(tmp_path)
    fixture_tool = ExternalTool(
        id="nuclei",
        binary=str(fixture_binary),
        build_command=lambda target: [str(fixture_binary), "-u", target],
        parse_output=lambda stdout: [
            __import__("json").loads(line) for line in stdout.splitlines() if line.strip()
        ],
        normalizer=__import__("adapters.scanner.nuclei", fromlist=["NucleiAdapter"]).NucleiAdapter(),
    )

    with patch("packs.runner._LIVE_TOOL_FACTORIES", {"nuclei": lambda options: fixture_tool}):
        results = asyncio.run(
            run_selected_packs(
                selections, _TESTCASES, _policy(), store,
                tool_checker=fake_checker, live_target_url="https://ai.example.com/api/",
            )
        )

    assert len(results) == 1
    assert results[0].status == "ran"
    assert results[0].summary["count"] == 1


def test_run_selected_packs_without_a_live_target_url_keeps_reporting_no_results_file(tmp_path) -> None:
    # Backward compatibility: omitting live_target_url (the default) must
    # behave exactly as it did before P3.1-3.
    web_scan_pack = AttackPack(
        id="web_scan", name="Web Vulnerability Scan", applies_to=("web",),
        testing_categories=("automated_scanning",), estimated_request_cost=50, tool_ids=("nuclei",),
    )
    selections = [PackSelection(web_scan_pack, True, "selected")]
    store = SQLiteStore(tmp_path / "runner.sqlite")

    def fake_checker(name: str) -> ToolStatus:
        return ToolStatus(name=name, available=True, path=f"/usr/bin/{name}", version=None, status="ok")

    results = asyncio.run(
        run_selected_packs(selections, _TESTCASES, _policy(), store, tool_checker=fake_checker)
    )

    assert len(results) == 1
    assert results[0].status == "skipped_no_results_file"
