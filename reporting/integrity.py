from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from core.contract import SCHEMA_VERSIONS
from storage.artifacts import sha256_file, write_json_artifact
from storage.sqlite import SQLiteStore

# P3.4-3 (roadmap v3.4.0 Production Hardening): the roadmap's own module
# list names this `evidence/integrity.py`, but this project already has
# a top-level `evidence/` *directory* used as the raw/sanitized output
# location (evidence/raw/, evidence/sanitized/, both gitignored --
# reporting/evidence.py's write_evidence_bundle writes there). Putting a
# Python package there too would collide with that existing runtime
# output directory, so this lives alongside reporting/evidence.py and
# reporting/sanitizer.py instead, which already own "raw/sanitized
# 분리" and redaction (this module's own job is additive: a per-run
# manifest + tamper detection on top of what those two already do).


@dataclass(frozen=True)
class ManifestEntry:
    evidence_id: str
    kind: str
    sanitized_path: str
    sanitized_sha256: str
    raw_path: str | None
    raw_sha256: str | None
    tamper_detected: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "evidence_id": self.evidence_id,
            "kind": self.kind,
            "sanitized_path": self.sanitized_path,
            "sanitized_sha256": self.sanitized_sha256,
            "raw_path": self.raw_path,
            "raw_sha256": self.raw_sha256,
            "tamper_detected": self.tamper_detected,
        }


@dataclass(frozen=True)
class RunManifest:
    run_id: str
    entries: list[ManifestEntry] = field(default_factory=list)

    @property
    def any_tamper_detected(self) -> bool:
        return any(entry.tamper_detected for entry in self.entries)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSIONS["evidence_manifest"],
            "run_id": self.run_id,
            "entry_count": len(self.entries),
            "any_tamper_detected": self.any_tamper_detected,
            "entries": [entry.to_dict() for entry in self.entries],
        }


def build_run_manifest(store: SQLiteStore, run_id: str) -> RunManifest:
    """Re-hashes every evidence file recorded under `run_id` right now
    and compares it against the hash recorded at write time (P3.4-3's
    "SHA-256 manifest" + tamper detection). A file that no longer
    exists, or whose content no longer matches its recorded hash, is
    flagged tamper_detected instead of silently trusted -- this is
    deterministic given the same on-disk files: re-running it without
    touching anything always reports the same result.
    """
    entries: list[ManifestEntry] = []
    for row in store.list_evidence(run_id):
        sanitized_path = Path(row["path"])
        current_sanitized_hash = sha256_file(sanitized_path) if sanitized_path.exists() else None
        raw_path_value = row["raw_path"] if "raw_path" in row.keys() else None
        raw_hash_value = row["raw_sha256"] if "raw_sha256" in row.keys() else None
        raw_path = Path(raw_path_value) if raw_path_value else None
        current_raw_hash = sha256_file(raw_path) if raw_path is not None and raw_path.exists() else None

        tamper_detected = current_sanitized_hash != row["sha256"]
        if raw_path is not None:
            tamper_detected = tamper_detected or current_raw_hash != raw_hash_value

        entries.append(
            ManifestEntry(
                evidence_id=row["id"],
                kind=row["kind"],
                sanitized_path=str(sanitized_path),
                sanitized_sha256=row["sha256"],
                raw_path=raw_path_value,
                raw_sha256=raw_hash_value,
                tamper_detected=tamper_detected,
            )
        )
    return RunManifest(run_id=run_id, entries=entries)


def write_manifest(directory: Path, manifest: RunManifest) -> Path:
    return write_json_artifact(directory, f"{manifest.run_id}_manifest.json", manifest.to_dict())
