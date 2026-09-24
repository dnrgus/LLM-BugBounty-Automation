from __future__ import annotations

import hashlib
import platform
import sys
from importlib import metadata
from pathlib import Path

# P5.0 WP-09 (v5.0 plan 8.1): the frozen v5 contract -- schema versions,
# CLI exit codes, finding states and report minimum fields live here so
# docs and tests can check them against one source. Changing anything in
# this file is a breaking change and needs a new major version.

CONTRACT_VERSION = "5.0"

SCHEMA_VERSIONS: dict[str, int] = {
    "scope_policy": 1,  # config/scope*.yaml (schema_version optional, defaults to 1)
    "scan_artifact": 1,  # `scan --source` output (validation/workflow.py)
    "evidence_manifest": 1,  # reporting/integrity.py RunManifest
    "validation_report": 1,  # `report` per-finding JSON
    "benchmark_dataset": 1,  # benchmarks/datasets/manifest.yaml
}

EXIT_CODES: dict[int, str] = {
    0: "success",
    1: "a gate failed (judge-benchmark, quality-gate, benchmark regression, release-check)",
    2: "scope denied (validate-scope) or command-line usage error (argparse)",
    3: "input or configuration error (missing file, invalid schema, unknown id)",
    130: "cancelled by the user (Ctrl-C) -- resumable where supported",
}

FINDING_STATES: dict[str, str] = {
    "candidate": "static or unvalidated signal; no dynamic verdict yet",
    "needs_review": "evidence exists but is not strong enough to confirm (missing context, judge conflict, low confidence)",
    "confirmed": "deterministically judged and reproduced under the recorded conditions",
    "rejected": "tested and not reproduced, or denied as expected",
    "unstable": "reproduced in some but not all attempts",
}

REQUIRED_REPORT_FIELDS: tuple[str, ...] = (
    "schema_version",
    "finding_id",
    "title",
    "status",
    "severity",
    "confidence",
    "validator_type",
    "reason",
    "evidence",
    "reproductions",
    "reproduction_steps",
    "limitations",
)


def check_schema_version(kind: str, value: object) -> None:
    expected = SCHEMA_VERSIONS[kind]
    if value is None:
        return
    if int(value) != expected:  # type: ignore[call-overload]
        raise ValueError(f"unsupported {kind} schema_version {value!r} (this build supports {expected})")


def package_version() -> str:
    try:
        return metadata.version("llm-bugbounty-automation")
    except metadata.PackageNotFoundError:
        return "unknown"


def execution_environment(**extra: object) -> dict[str, object]:
    """What `reproduce` records alongside its result: interpreter,
    platform, package/contract version, plus caller-supplied fields
    (target kind, config file hash, judges, attempts)."""
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "package_version": package_version(),
        "contract_version": CONTRACT_VERSION,
        **extra,
    }


def file_sha256(path: Path | str | None) -> str | None:
    if path is None or not Path(path).exists():
        return None
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
