from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from core.models import Finding

_WORD_RE = re.compile(r"[a-zA-Z0-9]+")
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def base_testcase_id(testcase_id: str) -> str:
    """Strips an adaptive-mutation suffix (e.g. "LLM-SP-001::mutation_abc" ->
    "LLM-SP-001") so mutation variants of the same seed testcase share a
    root cause."""
    return testcase_id.split("::", 1)[0]


def root_cause_key(category: str, testcase_id: str) -> str:
    payload = f"{category}|{base_testcase_id(testcase_id)}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def validation_root_cause_key(validator_type: str, static_candidate_id: str, target_entity: str) -> str:
    """P4.1-E (roadmap v4.1.0 Dynamic Validation Expansion): a
    validation-task-originated Finding's testcase_id is a fresh random
    ValidationTask id every time the same candidate is re-validated
    against the same target, so root_cause_key's testcase_id-based key
    would treat every re-run as a brand-new root cause. This key is
    deterministic across re-runs instead: same static candidate + same
    target + same validator always dedups together, per the roadmap's
    own instruction ("Dedup key = candidate fingerprint + target entity
    + validator_type").
    """
    payload = f"validation|{validator_type}|{static_candidate_id}|{target_entity}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _exact_key(finding: Finding) -> str:
    if finding.reproduction_spec.get("type") == "validation":
        return validation_root_cause_key(
            str(finding.reproduction_spec.get("validator_type", "")),
            finding.static_candidate_id or "",
            str(finding.reproduction_spec.get("target_entity", "")),
        )
    return root_cause_key(finding.category, finding.testcase_id)


def _title_tokens(title: str) -> set[str]:
    return {token.lower() for token in _WORD_RE.findall(title)}


def _title_similarity(a: str, b: str) -> float:
    tokens_a, tokens_b = _title_tokens(a), _title_tokens(b)
    if not tokens_a or not tokens_b:
        return 0.0
    overlap = len(tokens_a & tokens_b)
    union = len(tokens_a | tokens_b)
    return overlap / union if union else 0.0


@dataclass(frozen=True)
class FindingCluster:
    root_cause_key: str
    category: str
    representative_title: str
    severity: str
    max_confidence: float
    finding_ids: list[str] = field(default_factory=list)
    testcase_ids: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.finding_ids)

    def to_dict(self) -> dict[str, object]:
        return {
            "root_cause_key": self.root_cause_key,
            "category": self.category,
            "representative_title": self.representative_title,
            "severity": self.severity,
            "max_confidence": self.max_confidence,
            "finding_ids": self.finding_ids,
            "testcase_ids": self.testcase_ids,
            "count": self.count,
        }


def cluster_findings(findings: list[Finding], title_similarity_threshold: float = 0.6) -> list[FindingCluster]:
    """Groups findings into root-cause clusters.

    Two findings merge when either:
    - they share (category, base testcase id) -- e.g. mutation variants of
      the same seed testcase (exact/heuristic dedup); or
    - their category matches and titles overlap above the similarity
      threshold -- catches the same root cause surfaced via a different
      testcase (title/description similarity).

    This is a single-pass greedy grouping, not full pairwise clustering, by
    design: v1 only needs exact/heuristic + title-similarity dedup, and
    embedding-based clustering is deferred to v2 (see design doc section 16).

    P3.4-4 (roadmap v3.4.0 Production Hardening): the exact-key case (the
    common one -- mutation/adaptive variants of the same seed testcase,
    which is exactly what dominates a large scan's finding volume) is an
    O(1) dict lookup instead of a linear scan of every bucket seen so
    far, avoiding this function's own docstring's "quadratic dedup" risk
    for that path. The title-similarity fallback is still a bounded
    linear scan -- true sub-quadratic text similarity search is real
    scope creep here and, per the note above, is v2's job anyway.
    """
    buckets: list[dict[str, object]] = []
    buckets_by_key: dict[str, dict[str, object]] = {}

    for finding in findings:
        exact_key = _exact_key(finding)
        is_validation_origin = finding.reproduction_spec.get("type") == "validation"
        bucket = buckets_by_key.get(exact_key)
        # A validation-origin finding's exact key (candidate + target
        # entity + validator_type) is already the deterministic
        # identity the roadmap asks for -- it never falls back to
        # title-similarity fuzzy matching, which could otherwise merge
        # two different targets that happen to share a generic title
        # (e.g. "auth validation: AS-1" probed against two resources).
        if bucket is None and not is_validation_origin:
            bucket = next(
                (
                    b
                    for b in buckets
                    if b["category"] == finding.category
                    and _title_similarity(b["members"][0].title, finding.title) >= title_similarity_threshold
                ),
                None,
            )
        if bucket is None:
            bucket = {"key": exact_key, "category": finding.category, "members": [finding]}
            buckets.append(bucket)
            buckets_by_key[exact_key] = bucket
        else:
            bucket["members"].append(finding)
            buckets_by_key.setdefault(exact_key, bucket)

    clusters: list[FindingCluster] = []
    for bucket in buckets:
        members: list[Finding] = bucket["members"]
        representative = max(members, key=lambda f: (_SEVERITY_RANK.get(f.severity, 0), f.confidence))
        clusters.append(
            FindingCluster(
                root_cause_key=str(bucket["key"]),
                category=str(bucket["category"]),
                representative_title=representative.title,
                severity=representative.severity,
                max_confidence=max(f.confidence for f in members),
                finding_ids=[f.id for f in members],
                testcase_ids=sorted({f.testcase_id for f in members}),
            )
        )
    return clusters
