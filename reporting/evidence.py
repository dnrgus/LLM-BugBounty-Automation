from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from reporting.sanitizer import SanitizedArtifact, sanitize_artifact
from storage.artifacts import sha256_file, write_json_artifact


@dataclass(frozen=True)
class EvidenceBundle:
    raw_path: Path
    sanitized_path: Path
    redaction_log_path: Path
    raw_sha256: str
    sanitized_sha256: str
    redactions: list[dict[str, object]]

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["raw_path"] = str(self.raw_path)
        data["sanitized_path"] = str(self.sanitized_path)
        data["redaction_log_path"] = str(self.redaction_log_path)
        return data


def write_evidence_bundle(
    raw_dir: Path,
    sanitized_dir: Path,
    filename: str,
    payload: dict[str, Any],
) -> EvidenceBundle:
    raw_path = write_json_artifact(raw_dir, filename, payload)
    sanitized: SanitizedArtifact = sanitize_artifact(raw_path, sanitized_dir)
    return EvidenceBundle(
        raw_path=raw_path,
        sanitized_path=sanitized.path,
        redaction_log_path=sanitized.log_path,
        raw_sha256=sha256_file(raw_path),
        sanitized_sha256=sha256_file(sanitized.path),
        redactions=[asdict(item) for item in sanitized.redactions],
    )
