from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

from benchmarks.ground_truth import load_ground_truth
from benchmarks.matcher import match_findings_to_ground_truth
from benchmarks.metrics import compute_accuracy_metrics

# P4.7 WP-07/WP-08 (v5.0 plan 7.1-7.2): runs the fixed benchmark dataset,
# keeping TP/FP/FN, false-negative root causes, reproduction counts and
# stability (error/timeout/crash) as separate numbers. One failing target
# never stops the rest.

MANIFEST_SCHEMA_VERSION = 1
MISS_REASONS = (
    "unsupported_framework",
    "dataflow_cut",
    "auth_context_missing",
    "validator_limitation",
    "judge_false_negative",
    "policy_blocked",
    "unknown",
)
DEFAULT_TARGET_TIMEOUT_S = 60.0
_SUPPORTED_SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx"}


@dataclass(frozen=True)
class DatasetTarget:
    id: str
    group: str
    kind: str
    ground_truth: str
    path: str | None = None
    path_env: str | None = None
    target: str | None = None
    holdout: bool = False

    def resolved_path(self) -> str | None:
        if self.path_env:
            return os.environ.get(self.path_env)
        return self.path


@dataclass(frozen=True)
class Dataset:
    name: str
    targets: list[DatasetTarget] = field(default_factory=list)


def load_dataset(path: Path | str) -> Dataset:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if int(data.get("schema_version", 0)) != MANIFEST_SCHEMA_VERSION:
        raise ValueError(f"unsupported dataset manifest schema_version: {data.get('schema_version')!r}")
    targets = []
    for entry in data.get("targets", []):
        if entry["kind"] not in {"source", "llm_target", "external"}:
            raise ValueError(f"target {entry.get('id')!r}: unknown kind {entry['kind']!r}")
        targets.append(
            DatasetTarget(
                id=str(entry["id"]), group=str(entry["group"]), kind=str(entry["kind"]),
                ground_truth=str(entry["ground_truth"]), path=entry.get("path"), path_env=entry.get("path_env"),
                target=entry.get("target"), holdout=bool(entry.get("holdout", False)),
            )
        )
    return Dataset(name=str(data.get("name", "dataset")), targets=targets)


def _classify_miss(truth: Any) -> str:
    reason = getattr(truth, "expected_miss_reason", None)
    if reason in MISS_REASONS:
        return str(reason)
    if Path(str(truth.file)).suffix not in _SUPPORTED_SOURCE_SUFFIXES:
        return "unsupported_framework"
    return "unknown"


def _score_source(target: DatasetTarget, path: str) -> dict[str, object]:
    from source.audit import collect_source_items

    entry = load_ground_truth(target.ground_truth)
    _, items = collect_source_items(path)
    result = match_findings_to_ground_truth(items, entry.findings)
    truths = {truth.id: truth for truth in entry.findings}
    return {
        "metrics": result.metrics.to_dict(),
        "false_negatives": [
            {"id": truth_id, "reason": _classify_miss(truths[truth_id]), "expected": truths[truth_id].expected_miss_reason is not None}
            for truth_id in result.missed_ground_truth_ids
        ],
        "false_positive_locations": result.unmatched_item_locations,
        "ground_truth_count": len(entry.findings),
    }


def _score_llm_target(target: DatasetTarget) -> dict[str, object]:
    from core.orchestrator import run_sample_pipeline
    from scope.policy import PolicyEngine
    from storage.sqlite import SQLiteStore
    from testcase.loader import load_testcases

    truth = yaml.safe_load(Path(target.ground_truth).read_text(encoding="utf-8")) or {}
    expected = {str(item["id"]): item for item in truth.get("expected_confirmed", [])}
    with tempfile.TemporaryDirectory() as scratch:
        store = SQLiteStore(Path(scratch) / "bench.sqlite")
        previous = Path.cwd()
        os.chdir(scratch)  # keep evidence/report side effects out of the repo
        try:
            result = asyncio.run(
                run_sample_pipeline(
                    PolicyEngine.from_yaml(previous / "config/scope.example.yaml"),
                    load_testcases(previous / "testcase/suites/basic.yaml"),
                    store, target_kind=str(target.target),
                )
            )
        finally:
            os.chdir(previous)
        findings = store.list_findings([str(result["run_id"])])
        confirmed = {f.testcase_id for f in findings if f.status.value == "confirmed"}
        attempts = successes = 0
        for finding in findings:
            for row in store.list_reproductions(finding.id):
                attempts += int(row["attempts"])
                successes += int(row["successes"])

    tp = sorted(confirmed & set(expected))
    fp = sorted(confirmed - set(expected))
    fn = sorted(set(expected) - confirmed)
    return {
        "metrics": compute_accuracy_metrics(len(tp), len(fp), len(fn)).to_dict(),
        "false_negatives": [
            {"id": ident, "reason": expected[ident].get("expected_miss_reason") or "unknown",
             "expected": bool(expected[ident].get("expected_miss_reason"))}
            for ident in fn
        ],
        "false_positive_locations": fp,
        "ground_truth_count": len(expected),
        "confirmed_testcases": sorted(confirmed),
        "reproduction": {"attempts": attempts, "successes": successes},
    }


def _run_with_timeout(fn: Callable[[], dict[str, object]], timeout_s: float) -> tuple[str, dict[str, object] | None, str | None]:
    """("ok"|"timeout"|"error", result, detail). A timed-out worker thread
    can't be killed; it is abandoned and reported, never waited on."""
    pool = ThreadPoolExecutor(max_workers=1)
    future = pool.submit(fn)
    try:
        return "ok", future.result(timeout=timeout_s), None
    except FutureTimeout:
        return "timeout", None, f"exceeded {timeout_s}s"
    except Exception as exc:  # noqa: BLE001 -- crash isolation is the point
        return "error", None, "".join(traceback.format_exception_only(type(exc), exc)).strip()
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


def run_dataset(dataset: Dataset, timeout_s: float = DEFAULT_TARGET_TIMEOUT_S) -> dict[str, object]:
    per_target: list[dict[str, object]] = []
    for target in dataset.targets:
        started = time.monotonic()
        record: dict[str, object] = {"id": target.id, "group": target.group, "kind": target.kind, "holdout": target.holdout}
        if target.kind in {"source", "external"}:
            path = target.resolved_path()
            if not path or not Path(path).exists():
                record.update(status="skipped", detail=f"path not available ({target.path_env or target.path})")
                per_target.append(record)
                continue
            status, result, detail = _run_with_timeout(lambda: _score_source(target, path), timeout_s)
        else:
            status, result, detail = _run_with_timeout(lambda: _score_llm_target(target), timeout_s)
        record.update(status=status, elapsed_s=round(time.monotonic() - started, 3))
        if detail:
            record["detail"] = detail
        if result:
            record.update(result)
        per_target.append(record)
    return {"dataset": dataset.name, "targets": per_target, **summarize(per_target)}


def _aggregate(records: list[dict[str, object]]) -> dict[str, object]:
    tp = sum(int(r["metrics"]["true_positive"]) for r in records if "metrics" in r)
    fp = sum(int(r["metrics"]["false_positive"]) for r in records if "metrics" in r)
    fn = sum(int(r["metrics"]["false_negative"]) for r in records if "metrics" in r)
    return {
        "targets": len(records),
        "ground_truth_findings": sum(int(r.get("ground_truth_count", 0)) for r in records),
        **compute_accuracy_metrics(tp, fp, fn).to_dict(),
    }


def summarize(per_target: list[dict[str, object]]) -> dict[str, object]:
    scored = [r for r in per_target if r["status"] == "ok"]
    groups: dict[str, list[dict[str, object]]] = {}
    for record in scored:
        groups.setdefault(str(record["group"]), []).append(record)
    miss_reasons = {reason: 0 for reason in MISS_REASONS}
    for record in scored:
        for miss in record.get("false_negatives", []):
            miss_reasons[str(miss["reason"])] = miss_reasons.get(str(miss["reason"]), 0) + 1
    stability = {status: sum(1 for r in per_target if r["status"] == status) for status in ("ok", "error", "timeout", "skipped")}
    return {
        "overall": _aggregate([r for r in scored if not r["holdout"]]),
        "holdout": _aggregate([r for r in scored if r["holdout"]]),
        "by_group": {group: _aggregate(records) for group, records in sorted(groups.items())},
        "false_negative_reasons": miss_reasons,
        "stability": stability,
    }


def baseline_snapshot(report: dict[str, object]) -> dict[str, object]:
    """The comparable subset of a report (no timings)."""
    return {
        "dataset": report["dataset"],
        "targets": {
            str(r["id"]): {"status": r["status"], **({"metrics": r["metrics"]} if "metrics" in r else {})}
            for r in report["targets"]  # type: ignore[union-attr]
        },
    }


def compare_to_baseline(report: dict[str, object], baseline: dict[str, object]) -> list[str]:
    """Regressions: a target that got worse (fewer TP, more FP/FN) or
    stopped running cleanly. Improvements and new targets aren't
    regressions."""
    regressions: list[str] = []
    current = baseline_snapshot(report)["targets"]
    for target_id, before in baseline.get("targets", {}).items():  # type: ignore[union-attr]
        after = current.get(target_id)  # type: ignore[union-attr]
        if after is None:
            regressions.append(f"{target_id}: missing from current run")
            continue
        if before["status"] == "ok" and after["status"] != "ok":
            regressions.append(f"{target_id}: status {before['status']} -> {after['status']}")
            continue
        if "metrics" not in before or "metrics" not in after:
            continue
        b, a = before["metrics"], after["metrics"]
        if a["true_positive"] < b["true_positive"]:
            regressions.append(f"{target_id}: true_positive {b['true_positive']} -> {a['true_positive']}")
        if a["false_positive"] > b["false_positive"]:
            regressions.append(f"{target_id}: false_positive {b['false_positive']} -> {a['false_positive']}")
        if a["false_negative"] > b["false_negative"]:
            regressions.append(f"{target_id}: false_negative {b['false_negative']} -> {a['false_negative']}")
    return regressions


def write_baseline(report: dict[str, object], path: Path | str) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(baseline_snapshot(report), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target
