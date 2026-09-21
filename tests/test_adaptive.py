import json
import subprocess
import sys
from pathlib import Path

from adapters.llm.pyrit import PyRITAdapter
from attacks.adaptive import AdaptivePlanner
from storage.sqlite import SQLiteStore
from testcase.loader import load_testcases


def _pyrit_result():
    results = PyRITAdapter().parse_file(
        Path("tests/fixtures/tools/pyrit-results.json"),
        run_id="run_1",
        target_id="target_1",
        version="0.5",
    )
    return results[0]


def _testcase():
    testcases = load_testcases(Path("testcase/suites/basic.yaml"))
    return next(case for case in testcases if case.id == "LLM-TOOL-001")


def test_adaptive_planner_builds_plan_from_pyrit_result() -> None:
    result = _pyrit_result()
    testcase = _testcase()
    plan = AdaptivePlanner().plan_from_result(result, testcase)
    assert plan.testcase_id == "LLM-TOOL-001"
    assert plan.seed_title == result.title
    strategies = [mutation.strategy for mutation in plan.mutations]
    assert strategies == ["roleplay", "json_wrap", "multi_turn_split"]
    assert all(mutation.testcase_id == "LLM-TOOL-001" for mutation in plan.mutations)


def test_adaptive_planner_mutations_can_be_stored(tmp_path: Path) -> None:
    result = _pyrit_result()
    testcase = _testcase()
    plan = AdaptivePlanner().plan_from_result(result, testcase)
    store = SQLiteStore(tmp_path / "adaptive.sqlite")
    store.initialize()
    for mutation in plan.mutations:
        store.insert_mutation(mutation.to_record())
    with store.connect() as conn:
        rows = conn.execute("select strategy from mutations order by strategy").fetchall()
    assert {row["strategy"] for row in rows} == {"roleplay", "json_wrap", "multi_turn_split"}


def test_adaptive_plan_cli_outputs_json() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "adaptive-plan",
            "--input",
            "tests/fixtures/tools/pyrit-results.json",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(result.stdout)
    assert len(payload["plans"]) == 1
    plan = payload["plans"][0]
    assert plan["testcase_id"] == "LLM-TOOL-001"
    assert {mutation["strategy"] for mutation in plan["mutations"]} == {
        "roleplay",
        "json_wrap",
        "multi_turn_split",
    }
