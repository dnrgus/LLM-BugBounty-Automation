from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

import httpx

from scope.policy import PolicyEngine
from source.endpoints import EndpointSpec
from validation.auth_contexts import AuthContextSet, TesterAccount, object_id_candidates
from validation.auth_validator import AuthObservation, compare_auth_contexts

# P4.5 WP-02 (v5.0 plan 5.2): object-level access comparison between two
# tester-owned accounts. Deliberately narrow:
# - read-only methods only; anything state-changing stays needs_review,
# - only object ids the tester declared as owned by their own test
#   accounts are ever requested (no id enumeration or guessing),
# - every request goes through PolicyEngine (scope + method gate),
# - without two usable accounts nothing is sent and the reason is kept.

VERDICT_CONFIRMED = "confirmed"
VERDICT_REJECTED = "rejected"
VERDICT_NEEDS_REVIEW = "needs_review"


def _hash(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class ResponseFingerprint:
    """Status + structure + hashed key-field values -- never raw bodies
    or raw field values, which may be the very data being protected."""

    context_id: str
    status_code: int | None
    content_type: str | None
    body_shape: str | None
    field_hashes: dict[str, str] = field(default_factory=dict)
    error: str | None = None

    @classmethod
    def from_observation(cls, observation: AuthObservation) -> ResponseFingerprint:
        return cls(
            context_id=observation.context_id,
            status_code=observation.status_code,
            content_type=observation.content_type,
            body_shape=observation.body_shape,
            field_hashes={key: _hash(value) for key, value in observation.selected_fields.items()},
            error=observation.error,
        )

    @property
    def success(self) -> bool:
        return self.status_code is not None and 200 <= self.status_code < 300

    def to_dict(self) -> dict[str, object]:
        return {
            "context_id": self.context_id,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "body_shape": self.body_shape,
            "field_hashes": dict(self.field_hashes),
            "error": self.error,
        }


@dataclass(frozen=True)
class ObjectAccessResult:
    endpoint_id: str
    method: str
    object_param: str | None
    owner_context: str | None
    other_context: str | None
    verdict: str
    reason: str
    requested_url: str | None = None
    fingerprints: list[ResponseFingerprint] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "endpoint_id": self.endpoint_id,
            "method": self.method,
            "object_param": self.object_param,
            "owner_context": self.owner_context,
            "other_context": self.other_context,
            "verdict": self.verdict,
            "reason": self.reason,
            "requested_url": self.requested_url,
            "fingerprints": [fingerprint.to_dict() for fingerprint in self.fingerprints],
        }


def _needs_review(spec: EndpointSpec, reason: str, object_param: str | None = None) -> ObjectAccessResult:
    return ObjectAccessResult(spec.id, spec.method, object_param, None, None, VERDICT_NEEDS_REVIEW, reason)


def _fill_path(spec: EndpointSpec, param: str, value: str) -> str:
    path = spec.path
    for token in (f"<int:{param}>", f"<string:{param}>", f"<{param}>", f"{{{param}}}", f":{param}", f"[{param}]"):
        path = path.replace(token, value)
    return path


def compare_verdict(owner: ResponseFingerprint, other: ResponseFingerprint) -> tuple[str, str]:
    if owner.error or other.error or owner.status_code is None or other.status_code is None:
        return VERDICT_NEEDS_REVIEW, "request error on one side; no conclusion drawn"
    if not owner.success:
        return VERDICT_NEEDS_REVIEW, "owner could not read its own object; the baseline is invalid"
    if not other.success:
        return VERDICT_REJECTED, f"other account was denied (status {other.status_code})"
    if owner.body_shape != other.body_shape:
        return VERDICT_NEEDS_REVIEW, "both succeeded but response structure differs"
    if not owner.field_hashes:
        return VERDICT_NEEDS_REVIEW, "both succeeded with the same structure, but no key fields were compared"
    if owner.field_hashes == other.field_hashes:
        return VERDICT_CONFIRMED, "other account received the owner's object (matching key-field hashes)"
    return VERDICT_NEEDS_REVIEW, "both succeeded but key-field values differ"


async def validate_object_access(
    spec: EndpointSpec,
    base_url: str,
    contexts: AuthContextSet,
    policy: PolicyEngine,
    key_fields: list[str] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> ObjectAccessResult:
    if spec.risk != "read_only":
        return _needs_review(spec, "state-changing method: object access comparison is not automated")

    path_ids = [candidate["name"] for candidate in object_id_candidates(spec) if candidate["location"] == "path"]
    if not path_ids:
        return _needs_review(spec, "no path object-identifier candidate on this endpoint")
    param = path_ids[0]

    accounts: list[TesterAccount] = [account for account in contexts.usable_accounts() if param in account.owned_objects]
    if len(accounts) < 2:
        return _needs_review(
            spec, f"needs two usable tester accounts that each declare an owned '{param}'; found {len(accounts)}", param
        )
    owner, other = accounts[0], accounts[1]
    url = base_url.rstrip("/") + _fill_path(spec, param, owner.owned_objects[param])

    decision = policy.validate_request(url, spec.method)
    if not decision.allowed:
        return ObjectAccessResult(
            spec.id, spec.method, param, owner.context.id, other.context.id, VERDICT_NEEDS_REVIEW,
            f"blocked by policy before sending: {decision.reason}", requested_url=url,
        )

    comparison = await compare_auth_contexts(
        url, spec.method, owner.context, other.context, policy, selected_fields=key_fields, transport=transport
    )
    fingerprints = [ResponseFingerprint.from_observation(observation) for observation in comparison.observations]
    if len(fingerprints) != 2:
        return ObjectAccessResult(
            spec.id, spec.method, param, owner.context.id, other.context.id, VERDICT_NEEDS_REVIEW,
            "comparison did not produce two observations", requested_url=url,
        )
    verdict, reason = compare_verdict(fingerprints[0], fingerprints[1])
    return ObjectAccessResult(
        spec.id, spec.method, param, owner.context.id, other.context.id, verdict, reason,
        requested_url=url, fingerprints=fingerprints,
    )
