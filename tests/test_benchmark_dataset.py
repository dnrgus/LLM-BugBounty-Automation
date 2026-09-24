"""P4.7 WP-07/WP-08 (v5.0 plan 7.1-7.4): benchmark dataset, TP/FP/FN with
miss-reason taxonomy, stability accounting, and baseline regression."""

import json
import time
from pathlib import Path

import pytest

from benchmarks.dataset import (
    MISS_REASONS,
    _run_with_timeout,
    compare_to_baseline,
    load_dataset,
    run_dataset,
    write_baseline,
)
from cli import main

MANIFEST = Path("benchmarks/datasets/manifest.yaml")
BASELINE = Path("benchmarks/baselines/baseline.json")


def _manifest(tmp_path: Path, targets: list[dict]) -> Path:
    path = tmp_path / "manifest.yaml"
    path.write_text(json.dumps({"schema_version": 1, "name": "t", "targets": targets}), encoding="utf-8")
    return path


def test_manifest_rejects_unknown_schema_and_kind(tmp_path: Path) -> None:
    bad_schema = tmp_path / "a.yaml"
    bad_schema.write_text("schema_version: 9\ntargets: []\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_dataset(bad_schema)
    with pytest.raises(ValueError):
        load_dataset(_manifest(tmp_path, [{"id": "x", "group": "g", "kind": "magic", "ground_truth": "x"}]))


def test_default_dataset_reports_separate_tp_fp_fn_and_miss_reasons() -> None:
    report = run_dataset(load_dataset(MANIFEST))
    assert report["stability"] == {"ok": 8, "error": 0, "timeout": 0, "skipped": 0}
    overall = report["overall"]
    assert overall["targets"] == 7 and overall["ground_truth_findings"] == 14  # dataset size stated with the numbers
    assert (overall["true_positive"], overall["false_positive"], overall["false_negative"]) == (12, 0, 2)
    assert report["holdout"]["targets"] == 1
    assert report["false_negative_reasons"]["dataflow_cut"] == 2
    assert report["false_negative_reasons"]["policy_blocked"] == 1
    assert set(report["false_negative_reasons"]) == set(MISS_REASONS)
    assert set(report["by_group"]) == {"llm_app", "python_web", "jsts_web"}
    fake_llm = next(t for t in report["targets"] if t["id"] == "fake_llm")
    assert fake_llm["reproduction"]["attempts"] >= fake_llm["reproduction"]["successes"] > 0


def test_committed_baseline_has_no_regressions() -> None:
    report = run_dataset(load_dataset(MANIFEST))
    assert compare_to_baseline(report, json.loads(BASELINE.read_text(encoding="utf-8"))) == []


def test_missing_external_target_is_skipped_not_failed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BENCH_TEST_APP", raising=False)
    manifest = _manifest(tmp_path, [{"id": "ext", "group": "web_api", "kind": "external", "path_env": "BENCH_TEST_APP", "ground_truth": "x"}])
    report = run_dataset(load_dataset(manifest))
    assert report["targets"][0]["status"] == "skipped"
    assert report["stability"]["skipped"] == 1


def test_one_crashing_target_does_not_stop_the_others(tmp_path: Path) -> None:
    manifest = _manifest(
        tmp_path,
        [
            {"id": "broken", "group": "python_web", "kind": "source", "path": "tests/fixtures/source/sample_app", "ground_truth": str(tmp_path / "missing.yaml")},
            {"id": "sample", "group": "llm_app", "kind": "source", "path": "tests/fixtures/source/sample_app", "ground_truth": "benchmarks/corpus/sample_app.ground_truth.yaml"},
        ],
    )
    report = run_dataset(load_dataset(manifest))
    statuses = {t["id"]: t["status"] for t in report["targets"]}
    assert statuses == {"broken": "error", "sample": "ok"}
    assert "FileNotFoundError" in next(t for t in report["targets"] if t["id"] == "broken")["detail"]


def test_timeout_is_reported_separately() -> None:
    status, result, detail = _run_with_timeout(lambda: time.sleep(2) or {}, timeout_s=0.1)
    assert status == "timeout" and result is None and "0.1" in str(detail)


def test_compare_to_baseline_flags_each_regression_kind(tmp_path: Path) -> None:
    report = run_dataset(load_dataset(MANIFEST))
    baseline_path = write_baseline(report, tmp_path / "b.json")
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    baseline["targets"]["sample_app"]["metrics"]["true_positive"] = 5
    baseline["targets"]["express_app"]["metrics"]["false_positive"] = -1
    baseline["targets"]["gone"] = {"status": "ok"}
    regressions = compare_to_baseline(report, baseline)
    assert any(r.startswith("sample_app: true_positive") for r in regressions)
    assert any(r.startswith("express_app: false_positive") for r in regressions)
    assert "gone: missing from current run" in regressions


def test_cli_benchmark_exits_nonzero_on_regression(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    worse = json.loads(BASELINE.read_text(encoding="utf-8"))
    worse["targets"]["sample_app"]["metrics"]["true_positive"] = 99
    path = tmp_path / "worse.json"
    path.write_text(json.dumps(worse), encoding="utf-8")
    assert main(["benchmark", "--baseline", str(path)]) == 1
    assert main(["benchmark", "--baseline", str(BASELINE)]) == 0
    capsys.readouterr()
