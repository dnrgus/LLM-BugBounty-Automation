from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.models import SecretFinding


class TruffleHogAdapter:
    """Normalizes TruffleHog --json (newline-delimited) output.

    Never reads the "Raw" field. TruffleHog's own "Redacted" preview is the
    only secret-derived value that is allowed to leave this adapter.
    """

    tool = "trufflehog"

    def parse_file(
        self,
        path: Path | str,
        run_id: str,
        target_id: str,
        version: str | None = None,
    ) -> list[SecretFinding]:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
        records = [json.loads(line) for line in lines if line.strip()]
        return self.parse(records, run_id=run_id, target_id=target_id, version=version, raw_artifact_ref=str(path))

    def parse(
        self,
        records: list[dict[str, Any]],
        run_id: str,
        target_id: str,
        version: str | None = None,
        raw_artifact_ref: str | None = None,
    ) -> list[SecretFinding]:
        findings: list[SecretFinding] = []
        for record in records:
            findings.append(
                SecretFinding(
                    run_id=run_id,
                    target_id=target_id,
                    detector=str(record.get("DetectorName") or "unknown"),
                    source=self.tool,
                    location=_location(record),
                    verified=bool(record.get("Verified", False)),
                    redacted_secret=str(record.get("Redacted") or "[REDACTED]"),
                    raw_artifact_ref=raw_artifact_ref,
                    metadata={
                        "source_name": record.get("SourceName"),
                        "detector_type": record.get("DetectorType"),
                        "tool_version": version,
                    },
                )
            )
        return findings


def _location(record: dict[str, Any]) -> str:
    data = (record.get("SourceMetadata") or {}).get("Data") or {}
    filesystem = data.get("Filesystem") or {}
    file = filesystem.get("file")
    line = filesystem.get("line")
    if file and line:
        return f"{file}:{line}"
    if file:
        return str(file)
    git = data.get("Git") or {}
    if git.get("file"):
        commit = str(git.get("commit", ""))[:12]
        return f"{git['file']}@{commit}" if commit else str(git["file"])
    return "unknown"
