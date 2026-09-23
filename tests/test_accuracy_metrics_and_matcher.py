"""P4.4-B Metric Engine + P4.4-C Matching & Scoring (roadmap v4.4.0
Accuracy & Benchmark).
"""

from attack_surface.models import AttackSurfaceItem
from benchmarks.ground_truth import GroundTruthFinding
from benchmarks.matcher import match_findings_to_ground_truth
from benchmarks.metrics import aggregate_accuracy_metrics, compute_accuracy_metrics


def test_precision_recall_f1_perfect_score() -> None:
    metrics = compute_accuracy_metrics(true_positive=4, false_positive=0, false_negative=0)
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1 == 1.0
    assert metrics.false_positive_rate == 0.0
    assert metrics.false_negative_rate == 0.0


def test_precision_recall_with_misses_and_extras() -> None:
    metrics = compute_accuracy_metrics(true_positive=2, false_positive=1, false_negative=1)
    assert metrics.precision == 2 / 3
    assert metrics.recall == 2 / 3
    assert metrics.false_positive_rate == 1 / 3
    assert metrics.false_negative_rate == 1 / 3


def test_metrics_with_no_predictions_and_no_ground_truth_is_zero_not_nan() -> None:
    metrics = compute_accuracy_metrics(true_positive=0, false_positive=0, false_negative=0)
    assert metrics.precision == 0.0
    assert metrics.recall == 0.0
    assert metrics.f1 == 0.0


def test_aggregate_sums_raw_counts_not_averages_rates() -> None:
    a = compute_accuracy_metrics(true_positive=1, false_positive=0, false_negative=0)  # 100% recall, 1 gt item
    b = compute_accuracy_metrics(true_positive=9, false_positive=0, false_negative=1)  # 90% recall, 10 gt items
    aggregated = aggregate_accuracy_metrics([a, b])
    assert aggregated.true_positive == 10
    assert aggregated.false_negative == 1
    assert aggregated.recall == 10 / 11  # not the naive average of 100% and 90%


def _item(asset_type: str, file: str, line: int, **metadata) -> AttackSurfaceItem:
    return AttackSurfaceItem(
        source_type="source", asset_type=asset_type, location=f"{file}:{line}",
        metadata={"file": file, "line": line, **metadata},
    )


def test_matcher_perfect_match() -> None:
    truth = [GroundTruthFinding(id="t1", asset_type="dataflow", file="app.py", line=10, sink_type="os_command")]
    items = [_item("dataflow", "app.py", 10, sink_type="os_command")]
    result = match_findings_to_ground_truth(items, truth)
    assert result.matched_ground_truth_ids == ["t1"]
    assert result.missed_ground_truth_ids == []
    assert result.unmatched_item_locations == []
    assert result.metrics.precision == 1.0


def test_matcher_reports_missed_ground_truth() -> None:
    truth = [GroundTruthFinding(id="t1", asset_type="dataflow", file="app.py", sink_type="sql_injection")]
    items = [_item("dataflow", "app.py", 10, sink_type="os_command")]
    result = match_findings_to_ground_truth(items, truth)
    assert result.missed_ground_truth_ids == ["t1"]
    assert result.metrics.recall == 0.0


def test_matcher_only_penalizes_false_positives_within_ground_truth_asset_types() -> None:
    # A "parameter"/"endpoint" signal isn't a vulnerability claim the
    # ground truth characterizes, so it must never count as a false
    # positive even though it's unmatched.
    truth = [GroundTruthFinding(id="t1", asset_type="dataflow", file="app.py", line=10, sink_type="os_command")]
    items = [
        _item("dataflow", "app.py", 10, sink_type="os_command"),
        _item("parameter", "app.py", 5, name="req.query.x"),
        _item("endpoint", "app.py", 1, method="GET"),
    ]
    result = match_findings_to_ground_truth(items, truth)
    assert result.unmatched_item_locations == []
    assert result.metrics.false_positive == 0


def test_matcher_reports_unmatched_relevant_items_as_false_positives() -> None:
    truth = [GroundTruthFinding(id="t1", asset_type="dataflow", file="app.py", line=10, sink_type="os_command")]
    items = [
        _item("dataflow", "app.py", 10, sink_type="os_command"),
        _item("dataflow", "app.py", 30, sink_type="sql_injection"),  # not in ground truth
    ]
    result = match_findings_to_ground_truth(items, truth)
    assert result.metrics.false_positive == 1
    assert result.metrics.true_positive == 1


def test_matcher_does_not_double_count_one_item_against_two_ground_truth_entries() -> None:
    truth = [
        GroundTruthFinding(id="t1", asset_type="dataflow", file="app.py", line=10, sink_type="os_command"),
        GroundTruthFinding(id="t2", asset_type="dataflow", file="app.py", line=10, sink_type="os_command"),
    ]
    items = [_item("dataflow", "app.py", 10, sink_type="os_command")]
    result = match_findings_to_ground_truth(items, truth)
    assert len(result.matched_ground_truth_ids) == 1
    assert len(result.missed_ground_truth_ids) == 1


def test_matcher_to_dict_is_json_serializable() -> None:
    import json

    truth = [GroundTruthFinding(id="t1", asset_type="dataflow", file="app.py", line=10, sink_type="os_command")]
    items = [_item("dataflow", "app.py", 10, sink_type="os_command")]
    result = match_findings_to_ground_truth(items, truth)
    json.dumps(result.to_dict())
