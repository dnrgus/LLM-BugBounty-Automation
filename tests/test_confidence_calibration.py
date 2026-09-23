"""P4.4-E Confidence Calibration (roadmap v4.4.0 Accuracy & Benchmark) --
a reporting/analysis tool, never a live recalibration of any
AttackSurfaceItem's confidence value.
"""

import pytest

from attack_surface.models import AttackSurfaceItem
from benchmarks.calibration import compute_confidence_calibration, compute_confidence_calibration_across
from benchmarks.matcher import MatchResult
from benchmarks.metrics import compute_accuracy_metrics


def _item(confidence: float) -> AttackSurfaceItem:
    return AttackSurfaceItem(source_type="source", asset_type="dataflow", location="app.py:1", confidence=confidence)


def test_well_calibrated_when_true_positives_have_higher_confidence() -> None:
    result = MatchResult(
        matched_items=[_item(0.9), _item(0.8)],
        false_positive_items=[_item(0.3)],
        metrics=compute_accuracy_metrics(2, 1, 0),
    )
    calibration = compute_confidence_calibration(result)
    assert calibration.mean_true_positive_confidence == pytest.approx(0.85)
    assert calibration.mean_false_positive_confidence == pytest.approx(0.3)
    assert calibration.is_well_calibrated is True


def test_not_well_calibrated_when_false_positives_have_higher_confidence() -> None:
    result = MatchResult(
        matched_items=[_item(0.3)],
        false_positive_items=[_item(0.9)],
        metrics=compute_accuracy_metrics(1, 1, 0),
    )
    calibration = compute_confidence_calibration(result)
    assert calibration.is_well_calibrated is False


def test_well_calibrated_by_default_when_one_side_is_empty() -> None:
    result = MatchResult(matched_items=[_item(0.5)], false_positive_items=[], metrics=compute_accuracy_metrics(1, 0, 0))
    calibration = compute_confidence_calibration(result)
    assert calibration.false_positive_count == 0
    assert calibration.is_well_calibrated is True


def test_never_mutates_the_underlying_items_confidence() -> None:
    item = _item(0.5)
    result = MatchResult(matched_items=[item], false_positive_items=[], metrics=compute_accuracy_metrics(1, 0, 0))
    compute_confidence_calibration(result)
    assert item.confidence == 0.5


def test_compute_across_pools_multiple_match_results() -> None:
    result_a = MatchResult(matched_items=[_item(1.0)], false_positive_items=[], metrics=compute_accuracy_metrics(1, 0, 0))
    result_b = MatchResult(matched_items=[_item(0.5)], false_positive_items=[], metrics=compute_accuracy_metrics(1, 0, 0))
    calibration = compute_confidence_calibration_across([result_a, result_b])
    assert calibration.true_positive_count == 2
    assert calibration.mean_true_positive_confidence == 0.75


def test_to_dict_is_json_serializable() -> None:
    import json

    result = MatchResult(matched_items=[_item(0.5)], false_positive_items=[], metrics=compute_accuracy_metrics(1, 0, 0))
    calibration = compute_confidence_calibration(result)
    json.dumps(calibration.to_dict())
