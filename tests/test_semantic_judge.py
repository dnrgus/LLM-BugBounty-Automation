"""P4.6 WP-06 (v5.0 plan 6.3/6.4): semantic judge as a secondary layer --
deterministic / semantic / final verdicts, needs_review on conflict or
low confidence, model/prompt metadata recorded."""

import asyncio
import json
from pathlib import Path

import pytest

from core.models import FindingStatus
from core.orchestrator import run_sample_pipeline
from judges.semantic import (
    SEMANTIC_PROMPT_VERSION,
    LLMSemanticJudge,
    SemanticJudgeConfig,
    SemanticVerdict,
    combine_verdicts,
    load_semantic_judge_config,
    parse_semantic_output,
)
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from testcase.loader import load_testcases


def _verdict(violation, confidence=0.9):
    return SemanticVerdict(violation, confidence, "stub")


@pytest.mark.parametrize(
    ("deterministic", "semantic", "expected"),
    [
        (True, None, "confirmed"),
        (False, None, "rejected"),
        (True, _verdict(True), "confirmed"),
        (False, _verdict(False), "rejected"),
        (True, _verdict(False), "needs_review"),  # conflict
        (False, _verdict(True), "needs_review"),  # semantic alone never confirms
        (True, _verdict(True, 0.4), "needs_review"),  # low-confidence agreement
        (False, _verdict(False, 0.4), "rejected"),
        (True, _verdict(None, 0.0), "confirmed"),  # abstain keeps deterministic
    ],
)
def test_combine_verdicts_table(deterministic, semantic, expected) -> None:
    layered = combine_verdicts(deterministic, 1.0 if deterministic else 0.0, "det", semantic, min_confidence=0.7)
    assert layered.final == expected
    assert set(layered.to_dict()) == {"deterministic", "semantic", "final"}


def test_parse_semantic_output_is_robust() -> None:
    assert parse_semantic_output('noise {"violation": true, "confidence": 1.7, "reason": "x"} tail') == (True, 1.0, "x")
    assert parse_semantic_output("I think it is fine")[0] is None
    assert parse_semantic_output('{"violation": "yes"}')[0] is None


def test_llm_semantic_judge_records_model_and_prompt_metadata() -> None:
    prompts: list[str] = []

    def complete(prompt: str) -> str:
        prompts.append(prompt)
        return '{"violation": false, "confidence": 0.8, "reason": "refused"}'

    verdict = LLMSemanticJudge(complete, "stub-model").evaluate("policy", "attack prompt", "response text")
    assert verdict.violation is False
    assert verdict.metadata["model"] == "stub-model"
    assert verdict.metadata["prompt_version"] == SEMANTIC_PROMPT_VERSION
    assert len(str(verdict.metadata["prompt_sha256"])) == 64
    assert "attack prompt" in prompts[0] and "response text" in prompts[0]


def test_unavailable_semantic_judge_abstains_instead_of_crashing() -> None:
    def complete(prompt: str) -> str:
        raise RuntimeError("down")

    verdict = LLMSemanticJudge(complete, "m").evaluate("p", "q", "r")
    assert verdict.violation is None
    assert "unavailable" in verdict.reason


def test_load_semantic_judge_config(tmp_path: Path) -> None:
    path = tmp_path / "semantic.yaml"
    path.write_text("provider: openai_compatible\nbase_url: http://localhost:9\nmodel: m\nmin_confidence: 0.8\n", encoding="utf-8")
    config = load_semantic_judge_config(path)
    assert config.min_confidence == 0.8
    assert config.judge.model == "m"
    path.write_text("provider: other\nbase_url: x\nmodel: m\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_semantic_judge_config(path)


def _run(tmp_path: Path, semantic: SemanticJudgeConfig | None) -> tuple[dict, SQLiteStore]:
    store = SQLiteStore(tmp_path / "s.sqlite")
    result = asyncio.run(
        run_sample_pipeline(
            PolicyEngine.from_yaml("config/scope.example.yaml"),
            load_testcases("testcase/suites/basic.yaml"),
            store,
            semantic_judge=semantic,
        )
    )
    return result, store


def _stub(answer: dict) -> SemanticJudgeConfig:
    return SemanticJudgeConfig(LLMSemanticJudge(lambda prompt: json.dumps(answer), "stub-model"), min_confidence=0.7)


def test_pipeline_without_semantic_judge_is_unchanged(tmp_path: Path) -> None:
    result, store = _run(tmp_path, None)
    assert result["reproductions"]["confirmed"] == 1
    assert {f.status for f in store.list_findings([str(result["run_id"])])} == {FindingStatus.CONFIRMED}


def test_pipeline_agreeing_semantic_judge_keeps_confirmed_and_records_layers(tmp_path: Path) -> None:
    result, store = _run(tmp_path, _stub({"violation": True, "confidence": 0.95, "reason": "complied"}))
    findings = store.list_findings([str(result["run_id"])])
    assert [f.status for f in findings if f.status is not FindingStatus.NEEDS_REVIEW] == [FindingStatus.CONFIRMED]
    evidence = [row for row in store.list_evidence(str(result["run_id"])) if row["kind"] == "llm_response"]
    layers = json.loads(Path(evidence[0]["path"]).read_text(encoding="utf-8"))["judge_layers"]
    assert layers["semantic"]["metadata"]["model"] == "stub-model"
    assert "final" in layers and "deterministic" in layers


def test_pipeline_conflicting_semantic_judge_downgrades_to_needs_review(tmp_path: Path) -> None:
    result, store = _run(tmp_path, _stub({"violation": False, "confidence": 0.95, "reason": "looks safe"}))
    statuses = {f.status for f in store.list_findings([str(result["run_id"])])}
    assert FindingStatus.CONFIRMED not in statuses
    assert FindingStatus.NEEDS_REVIEW in statuses
