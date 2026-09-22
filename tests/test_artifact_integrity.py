"""P3.4-3 Artifact Integrity / Redaction (roadmap v3.4.0 Production Hardening).

Known-secret-corpus redaction is already covered by tests/test_reporting.py
(reporting/sanitizer.py) -- this file covers the new capability: a per-run
SHA-256 manifest with raw/sanitized provenance and tamper detection.
"""

import asyncio
import json
from pathlib import Path

from core.orchestrator import run_sample_pipeline
from reporting.evidence import write_evidence_bundle
from reporting.integrity import build_run_manifest, write_manifest
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from testcase.loader import load_testcases


def _policy() -> PolicyEngine:
    return PolicyEngine.from_yaml("config/scope.example.yaml")


def _record_one(store: SQLiteStore, run_id: str, tmp_path: Path, payload: dict[str, object]) -> str:
    bundle = write_evidence_bundle(tmp_path / "raw", tmp_path / "sanitized", "artifact.json", payload)
    evidence = store.record_evidence(run_id, "test_kind", bundle.sanitized_path, raw_path=bundle.raw_path)
    return evidence.id


def test_manifest_has_no_tamper_detected_for_untouched_files(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "integrity.sqlite")
    store.initialize()
    _record_one(store, "run_1", tmp_path, {"prompt": "hello"})

    manifest = build_run_manifest(store, "run_1")
    assert len(manifest.entries) == 1
    assert manifest.any_tamper_detected is False
    assert manifest.entries[0].raw_sha256 is not None
    assert manifest.entries[0].sanitized_sha256 is not None


def test_manifest_flags_tamper_when_the_sanitized_file_changes_after_recording(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "integrity.sqlite")
    store.initialize()
    _record_one(store, "run_2", tmp_path, {"prompt": "hello"})

    manifest_before = build_run_manifest(store, "run_2")
    sanitized_path = Path(manifest_before.entries[0].sanitized_path)
    sanitized_path.write_text('{"tampered": true}', encoding="utf-8")

    manifest_after = build_run_manifest(store, "run_2")
    assert manifest_after.any_tamper_detected is True
    assert manifest_after.entries[0].tamper_detected is True


def test_manifest_flags_tamper_when_the_raw_file_changes_after_recording(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "integrity.sqlite")
    store.initialize()
    _record_one(store, "run_3", tmp_path, {"prompt": "hello"})

    manifest_before = build_run_manifest(store, "run_3")
    raw_path = Path(manifest_before.entries[0].raw_path)
    raw_path.write_text('{"tampered": true}', encoding="utf-8")

    manifest_after = build_run_manifest(store, "run_3")
    assert manifest_after.any_tamper_detected is True


def test_manifest_flags_tamper_when_the_file_is_deleted(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "integrity.sqlite")
    store.initialize()
    _record_one(store, "run_4", tmp_path, {"prompt": "hello"})

    manifest_before = build_run_manifest(store, "run_4")
    Path(manifest_before.entries[0].sanitized_path).unlink()

    manifest_after = build_run_manifest(store, "run_4")
    assert manifest_after.any_tamper_detected is True


def test_manifest_is_deterministic_across_repeated_builds(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "integrity.sqlite")
    store.initialize()
    _record_one(store, "run_5", tmp_path, {"prompt": "a"})
    _record_one(store, "run_5", tmp_path, {"prompt": "b"})

    first = build_run_manifest(store, "run_5").to_dict()
    second = build_run_manifest(store, "run_5").to_dict()
    assert first == second


def test_record_evidence_without_raw_path_still_works(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "integrity.sqlite")
    store.initialize()
    bundle = write_evidence_bundle(tmp_path / "raw", tmp_path / "sanitized", "artifact.json", {"x": 1})
    evidence = store.record_evidence("run_6", "test_kind", bundle.sanitized_path)  # no raw_path
    assert evidence.raw_path is None
    assert evidence.raw_sha256 is None

    manifest = build_run_manifest(store, "run_6")
    assert manifest.entries[0].raw_path is None
    assert manifest.entries[0].tamper_detected is False


def test_write_manifest_produces_a_readable_json_file(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "integrity.sqlite")
    store.initialize()
    _record_one(store, "run_7", tmp_path, {"prompt": "hello"})
    manifest = build_run_manifest(store, "run_7")

    path = write_manifest(tmp_path / "manifests", manifest)
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk["run_id"] == "run_7"
    assert on_disk["entry_count"] == 1


def test_run_sample_pipeline_produces_an_artifact_manifest(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "pipeline.sqlite")
    testcases = load_testcases("testcase/suites/basic.yaml")
    result = asyncio.run(run_sample_pipeline(_policy(), testcases, store, target_kind="fake-llm"))

    assert result["artifact_manifest_tamper_detected"] is False
    manifest_path = Path(result["artifact_manifest"])
    assert manifest_path.exists()
    on_disk = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert on_disk["run_id"] == result["run_id"]
    assert on_disk["entry_count"] > 0
