from __future__ import annotations

from dataclasses import dataclass, field

from attack_surface.models import AttackSurfaceItem
from benchmarks.ground_truth import GroundTruthFinding
from benchmarks.metrics import AccuracyMetrics, compute_accuracy_metrics


@dataclass(frozen=True)
class MatchResult:
    matched_ground_truth_ids: list[str] = field(default_factory=list)
    missed_ground_truth_ids: list[str] = field(default_factory=list)
    unmatched_item_locations: list[str] = field(default_factory=list)
    metrics: AccuracyMetrics = field(default_factory=lambda: compute_accuracy_metrics(0, 0, 0))
    # P4.4-E (roadmap v4.4.0 Accuracy & Benchmark): the actual matched
    # (true-positive) and unmatched (false-positive) AttackSurfaceItem
    # objects, not just their ids/locations -- benchmarks/calibration.py
    # needs each item's own `confidence` value, which the string-only
    # fields above don't carry. Not included in to_dict()'s summary
    # (which stays lightweight); calibration.py consumes these fields
    # directly.
    matched_items: list[AttackSurfaceItem] = field(default_factory=list)
    false_positive_items: list[AttackSurfaceItem] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "matched_ground_truth_ids": self.matched_ground_truth_ids,
            "missed_ground_truth_ids": self.missed_ground_truth_ids,
            "unmatched_item_locations": self.unmatched_item_locations,
            "metrics": self.metrics.to_dict(),
        }


def match_findings_to_ground_truth(
    items: list[AttackSurfaceItem], ground_truth: list[GroundTruthFinding]
) -> MatchResult:
    """P4.4-C (roadmap v4.4.0 Accuracy & Benchmark): scores SOURCE
    MODE's AttackSurfaceItem output against a fixture's documented
    ground truth.

    Only items whose asset_type is one the ground truth set actually
    covers are considered candidate false positives -- a fixture's
    ground truth only documents *known vulnerabilities* (asset_type
    dataflow/secret today), not every detector this project has
    (endpoint/parameter/function/llm signals are legitimate output but
    aren't vulnerability claims a ground truth list characterizes, so
    they're never penalized as false positives here).
    """
    relevant_asset_types = {truth.asset_type for truth in ground_truth}
    relevant_items = [item for item in items if item.asset_type in relevant_asset_types]

    matched_ids: list[str] = []
    missed_ids: list[str] = []
    matched_item_ids: set[str] = set()
    matched_items: list[AttackSurfaceItem] = []

    for truth in ground_truth:
        match = next((item for item in relevant_items if item.id not in matched_item_ids and truth.matches(item)), None)
        if match is not None:
            matched_ids.append(truth.id)
            matched_item_ids.add(match.id)
            matched_items.append(match)
        else:
            missed_ids.append(truth.id)

    false_positive_items = [item for item in relevant_items if item.id not in matched_item_ids]
    unmatched_locations = [item.location for item in false_positive_items]

    metrics = compute_accuracy_metrics(
        true_positive=len(matched_ids), false_positive=len(unmatched_locations), false_negative=len(missed_ids)
    )
    return MatchResult(matched_ids, missed_ids, unmatched_locations, metrics, matched_items, false_positive_items)
