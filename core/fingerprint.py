from __future__ import annotations

import hashlib
import json
import subprocess
from typing import Any


def canonical_json(data: dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def current_git_commit() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()
    except Exception:
        return "unknown"


def build_environment_fingerprint(inputs: dict[str, Any]) -> dict[str, Any]:
    payload = dict(inputs)
    payload.setdefault("pipeline_git_commit_sha", current_git_commit())
    payload.setdefault("tool_versions", {})
    payload.setdefault("config_hash", "unknown")
    value = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    return {"fingerprint": value, "inputs": payload}

