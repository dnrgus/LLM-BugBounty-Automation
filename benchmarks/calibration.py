from __future__ import annotations

from dataclasses import dataclass

from benchmarks.matcher import MatchResult


@dataclass(frozen=True)
class ConfidenceCalibration:
    """P4.4-E (roadmap v4.4.0 Accuracy & Benchmark): a REPORTING/
    ANALYSIS tool, not a live recalibration -- this never changes any
    AttackSurfaceItem's actual `confidence` value (that would mean
    touching every static analyzer's hand-tuned confidence constants,
    a much bigger and riskier change than this phase calls for). It
    only asks: across a ground-truth run, did items that turned out to
    be true positives actually carry higher confidence, on average,
    than the ones that turned out to be false positives? If not,
    confidence isn't tracking correctness, and that's worth knowing
    even though this tool doesn't fix it by itself.
    """

    true_positive_count: int
    false_positive_count: int
    mean_true_positive_confidence: float
    mean_false_positive_confidence: float

    @property
    def is_well_calibrated(self) -> bool:
        """True when there's nothing to compare (one side is empty --
        that's not evidence of miscalibration) or when true positives
        carry confidence >= false positives on average."""
        if self.true_positive_count == 0 or self.false_positive_count == 0:
            return True
        return self.mean_true_positive_confidence >= self.mean_false_positive_confidence

    def to_dict(self) -> dict[str, object]:
        return {
            "true_positive_count": self.true_positive_count,
            "false_positive_count": self.false_positive_count,
            "mean_true_positive_confidence": self.mean_true_positive_confidence,
            "mean_false_positive_confidence": self.mean_false_positive_confidence,
            "is_well_calibrated": self.is_well_calibrated,
        }


def compute_confidence_calibration(match_result: MatchResult) -> ConfidenceCalibration:
    return _calibration_from_items(match_result.matched_items, match_result.false_positive_items)


def compute_confidence_calibration_across(match_results: list[MatchResult]) -> ConfidenceCalibration:
    """Same as compute_confidence_calibration, but pooling every
    matched/false-positive item across multiple corpus entries first --
    a fixture with only 1-2 ground-truth items doesn't produce a
    meaningful mean on its own."""
    matched_items = [item for result in match_results for item in result.matched_items]
    false_positive_items = [item for result in match_results for item in result.false_positive_items]
    return _calibration_from_items(matched_items, false_positive_items)


def _calibration_from_items(matched_items: list, false_positive_items: list) -> ConfidenceCalibration:
    tp_confidences = [item.confidence for item in matched_items]
    fp_confidences = [item.confidence for item in false_positive_items]
    return ConfidenceCalibration(
        true_positive_count=len(tp_confidences),
        false_positive_count=len(fp_confidences),
        mean_true_positive_confidence=sum(tp_confidences) / len(tp_confidences) if tp_confidences else 0.0,
        mean_false_positive_confidence=sum(fp_confidences) / len(fp_confidences) if fp_confidences else 0.0,
    )
