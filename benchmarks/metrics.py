from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AccuracyMetrics:
    """P4.4-B (roadmap v4.4.0 Accuracy & Benchmark): a general
    precision/recall/FPR/FNR/F1 engine, usable for any true_positive/
    false_positive/false_negative count -- not specific to ground-truth
    matching, so `judges/benchmark.py`'s own existing per-judge metrics
    could reuse this later without this module needing to know
    anything about judges.
    """

    true_positive: int
    false_positive: int
    false_negative: int

    @property
    def precision(self) -> float:
        denom = self.true_positive + self.false_positive
        return self.true_positive / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positive + self.false_negative
        return self.true_positive / denom if denom else 0.0

    @property
    def false_positive_rate(self) -> float:
        """Fraction of ALL predicted findings that don't match any
        ground truth (== 1 - precision). There is no bounded "true
        negative" space when scoring static findings against a finite
        ground-truth list (every non-finding would be a would-be true
        negative) -- this uses the security-benchmarking convention
        (fraction of reported findings that are false), not the
        classical TN-based FPR definition.
        """
        denom = self.true_positive + self.false_positive
        return self.false_positive / denom if denom else 0.0

    @property
    def false_negative_rate(self) -> float:
        denom = self.true_positive + self.false_negative
        return self.false_negative / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def to_dict(self) -> dict[str, object]:
        return {
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "false_negative": self.false_negative,
            "precision": self.precision,
            "recall": self.recall,
            "false_positive_rate": self.false_positive_rate,
            "false_negative_rate": self.false_negative_rate,
            "f1": self.f1,
        }


def compute_accuracy_metrics(true_positive: int, false_positive: int, false_negative: int) -> AccuracyMetrics:
    return AccuracyMetrics(true_positive, false_positive, false_negative)


def aggregate_accuracy_metrics(metrics: list[AccuracyMetrics]) -> AccuracyMetrics:
    """Sums raw TP/FP/FN counts across multiple corpus entries before
    computing rates -- NOT an average of each entry's own rates, which
    would weight a fixture with 1 ground-truth finding the same as one
    with 20."""
    return AccuracyMetrics(
        true_positive=sum(m.true_positive for m in metrics),
        false_positive=sum(m.false_positive for m in metrics),
        false_negative=sum(m.false_negative for m in metrics),
    )
