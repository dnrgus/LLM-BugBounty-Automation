from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from judges.ensemble import JudgeEnsemble
from testcase.schema import Testcase


@dataclass(frozen=True)
class BenchmarkCase:
    id: str
    testcase: Testcase
    response: str
    expected: bool
    label: str


@dataclass(frozen=True)
class BenchmarkMetrics:
    true_positive: int
    true_negative: int
    false_positive: int
    false_negative: int

    @property
    def precision(self) -> float:
        denom = self.true_positive + self.false_positive
        return 0.0 if denom == 0 else self.true_positive / denom

    @property
    def recall(self) -> float:
        denom = self.true_positive + self.false_negative
        return 0.0 if denom == 0 else self.true_positive / denom

    @property
    def false_positive_rate(self) -> float:
        denom = self.false_positive + self.true_negative
        return 0.0 if denom == 0 else self.false_positive / denom

    @property
    def false_negative_rate(self) -> float:
        denom = self.false_negative + self.true_positive
        return 0.0 if denom == 0 else self.false_negative / denom

    @property
    def f1(self) -> float:
        denom = self.precision + self.recall
        return 0.0 if denom == 0 else 2 * self.precision * self.recall / denom

    def to_dict(self) -> dict[str, float | int]:
        return {
            "true_positive": self.true_positive,
            "true_negative": self.true_negative,
            "false_positive": self.false_positive,
            "false_negative": self.false_negative,
            "precision": self.precision,
            "recall": self.recall,
            "false_positive_rate": self.false_positive_rate,
            "false_negative_rate": self.false_negative_rate,
            "f1": self.f1,
        }


def load_benchmark_cases(path: Path | str) -> list[BenchmarkCase]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    cases: list[BenchmarkCase] = []
    for item in data["cases"]:
        testcase = Testcase(**item["testcase"])
        testcase.validate()
        cases.append(
            BenchmarkCase(
                id=item["id"],
                testcase=testcase,
                response=item["response"],
                expected=bool(item["expected"]),
                label=item.get("label", "unknown"),
            )
        )
    return cases


def run_benchmark(cases: list[BenchmarkCase], ensemble: JudgeEnsemble | None = None) -> dict[str, Any]:
    judge = ensemble or JudgeEnsemble.default()
    tp = tn = fp = fn = 0
    results: list[dict[str, Any]] = []
    for case in cases:
        judgement = judge.judge("benchmark", case.testcase, case.response)
        actual = judgement.passed
        if actual and case.expected:
            tp += 1
        elif not actual and not case.expected:
            tn += 1
        elif actual and not case.expected:
            fp += 1
        else:
            fn += 1
        results.append(
            {
                "id": case.id,
                "expected": case.expected,
                "actual": actual,
                "label": case.label,
                "score": judgement.score,
                "reason": judgement.reason,
            }
        )
    metrics = BenchmarkMetrics(tp, tn, fp, fn)
    return {"metrics": metrics.to_dict(), "results": results}
