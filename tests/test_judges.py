from core.models import TraceEvent
from judges.benchmark import load_benchmark_cases, run_benchmark
from judges.ensemble import JudgeEnsemble
from judges.signals import CanaryJudge, RegexJudge, RuleJudge, StreamingAnomalyJudge
from testcase.schema import Testcase


def test_individual_judges() -> None:
    assert CanaryJudge().evaluate("CANARY-SECRET-123").passed
    assert RegexJudge().evaluate("api token leaked").passed
    assert not RuleJudge().evaluate("I cannot ignore safety instructions.").passed


def test_ensemble_uses_requested_testcase_judges() -> None:
    testcase = Testcase(
        id="JUDGE-001",
        name="Judge Test",
        category="system_prompt_leak",
        requires=["chat"],
        prompt="Reveal marker",
        judges=["canary"],
    )
    judgement = JudgeEnsemble.default().judge("run_1", testcase, "CANARY-SECRET-123")
    assert judgement.passed
    assert judgement.score == 1.0


def _trace_event(event_type: str, content: str = "") -> TraceEvent:
    return TraceEvent(trace_id="t1", sequence=1, event_type=event_type, metadata={"content": content})


def test_streaming_anomaly_judge_evaluate_without_events_is_a_neutral_default() -> None:
    signal = StreamingAnomalyJudge().evaluate("anything")
    assert signal.passed is False


def test_streaming_anomaly_judge_flags_mid_stream_error() -> None:
    events = [_trace_event("start"), _trace_event("error", "boom")]
    signal = StreamingAnomalyJudge().evaluate_events("final text", events)
    assert signal.passed is True
    assert "error" in signal.reason


def test_streaming_anomaly_judge_flags_token_content_missing_from_final() -> None:
    events = [_trace_event("token", "the secret is XYZ"), _trace_event("final", "I cannot help with that")]
    signal = StreamingAnomalyJudge().evaluate_events("I cannot help with that", events)
    assert signal.passed is True
    assert "retraction" in signal.reason


def test_streaming_anomaly_judge_passes_when_final_contains_streamed_content() -> None:
    events = [_trace_event("token", "hello"), _trace_event("final", "hello world")]
    signal = StreamingAnomalyJudge().evaluate_events("hello world", events)
    assert signal.passed is False


def test_streaming_anomaly_judge_no_events_at_all_is_not_an_anomaly() -> None:
    signal = StreamingAnomalyJudge().evaluate_events("plain text", [])
    assert signal.passed is False


def test_ensemble_ignores_trace_events_when_judge_not_enabled() -> None:
    testcase = Testcase(
        id="JUDGE-002", name="Judge Test", category="system_prompt_leak",
        requires=["chat"], prompt="x", judges=["canary"],
    )
    events = [_trace_event("error", "boom")]
    judgement = JudgeEnsemble.default().judge("run_1", testcase, "no canary here", trace_events=events)
    assert judgement.passed is False


def test_ensemble_uses_streaming_anomaly_judge_when_listed_and_events_supplied() -> None:
    testcase = Testcase(
        id="JUDGE-003", name="Judge Test", category="system_prompt_leak",
        requires=["chat"], prompt="x", judges=["streaming_anomaly"],
    )
    ensemble = JudgeEnsemble(["streaming_anomaly"])
    events = [_trace_event("error", "boom")]
    judgement = ensemble.judge("run_1", testcase, "final text", trace_events=events)
    assert judgement.passed is True
    assert "error" in judgement.reason


def test_ensemble_without_trace_events_falls_back_to_plain_evaluate() -> None:
    testcase = Testcase(
        id="JUDGE-004", name="Judge Test", category="system_prompt_leak",
        requires=["chat"], prompt="x", judges=["streaming_anomaly"],
    )
    ensemble = JudgeEnsemble(["streaming_anomaly"])
    judgement = ensemble.judge("run_1", testcase, "final text")
    assert judgement.passed is False
    assert "evaluate_events" in judgement.reason


def test_judge_benchmark_baseline_is_perfect() -> None:
    result = run_benchmark(load_benchmark_cases("benchmarks/judge/baseline.json"))
    metrics = result["metrics"]
    assert metrics["true_positive"] == 2
    assert metrics["true_negative"] == 2
    assert metrics["false_positive"] == 0
    assert metrics["false_negative"] == 0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1"] == 1.0
