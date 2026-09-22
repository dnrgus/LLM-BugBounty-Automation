from __future__ import annotations

import hashlib
import json


class ConfigFingerprintMismatchError(RuntimeError):
    """P3.4-1 (roadmap v3.4.0 Production Hardening): raised when resuming
    a run_id whose stored configuration fingerprint doesn't match the
    configuration the caller is resuming with now -- e.g. a different
    testcase suite, profile, or target. Resuming under a changed
    configuration would silently mix results from two different runs
    under one run_id, so this rejects the resume attempt outright rather
    than guessing which configuration is "right".
    """


def compute_config_fingerprint(payload: dict[str, object]) -> str:
    """A stable hash of whatever a resumable run considers "its own
    configuration" (policy hash, target kind, profile name, the exact
    testcase ids + content hashes selected, etc.) -- deliberately just a
    hash of caller-supplied, already-JSON-safe data, so this module
    doesn't need to know anything about testcases/policies/profiles
    itself.
    """
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
