"""Where every run writes its output.

All results live under one folder, results/BugBounty-Results/ (relative to
the working directory), so the repository root stays limited to the entry
point, code, config, tests and docs:

    results/BugBounty-Results/
        <target>_<timestamp>/     one folder per `bugbounty scan`
        _internal/
            runs/                 SQLite run stores, scan artifacts
            evidence/raw/         unredacted evidence bundles
            evidence/sanitized/   redacted evidence bundles
            reports/shareable/    manifests, cluster reports
            reports/validation/   `report` command output

BUGBOUNTY_RESULTS_DIR overrides the root (the test suite points it at a
temp dir so runs don't pile up in the real results folder). Resolved on
every call rather than at import so the override is always honored.
"""

from __future__ import annotations

import os
from pathlib import Path

RESULTS_DIR_ENV = "BUGBOUNTY_RESULTS_DIR"
DEFAULT_RESULTS_ROOT = Path("results") / "BugBounty-Results"


def results_root() -> Path:
    return Path(os.environ.get(RESULTS_DIR_ENV) or DEFAULT_RESULTS_ROOT)


def internal_dir(*parts: str) -> Path:
    return results_root().joinpath("_internal", *parts)


def runs_dir() -> Path:
    return internal_dir("runs")


def evidence_raw_dir() -> Path:
    return internal_dir("evidence", "raw")


def evidence_sanitized_dir() -> Path:
    return internal_dir("evidence", "sanitized")


def shareable_reports_dir() -> Path:
    return internal_dir("reports", "shareable")


def validation_reports_dir() -> Path:
    return internal_dir("reports", "validation")
