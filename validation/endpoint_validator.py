from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx

from scope.policy import PolicyEngine, method_risk
from validation.contract import ValidationStatus

# P4.1-B (roadmap v4.1.0 Dynamic Validation Expansion): never probe with
# a destructive verb regardless of what a candidate declares (POST/PUT/
# DELETE/PATCH are never sent) -- only these are ever safe to actually
# send, matching this project's "Policy before execution" /
# non-destructive discovery philosophy (live/discovery.py's own GET-only
# invariant, extended here to also allow HEAD/OPTIONS).
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}
_MAX_REDIRECT_HOPS = 5


def normalize_probe_methods(method_label: str) -> list[str]:
    """Normalizes this project's various route-method labels (bare
    verbs, "ROUTE"/"ANY" from source route extraction and Next.js Pages
    Router, or a "GET|POST"-joined multi-method string from the Python
    AST parser) into the set of methods actually safe to send. GET is
    always included as a baseline probe; any other *safe* method the
    candidate itself declares is also probed, but a declared destructive
    method (POST/PUT/DELETE/PATCH/...) is never sent -- its declaration
    is still visible to the caller via the original method_label, just
    never acted on here.
    """
    declared = {token.strip().upper() for token in method_label.split("|") if token.strip()}
    declared -= {"ROUTE", "ANY", ""}
    return sorted({"GET"} | (declared & _SAFE_METHODS))


@dataclass(frozen=True)
class EndpointObservation:
    method: str
    status_code: int | None
    content_type: str | None
    redirect_chain: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "method": self.method,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "redirect_chain": list(self.redirect_chain),
            "error": self.error,
        }


@dataclass(frozen=True)
class EndpointValidationEvidence:
    """Never interpreted as a confirmed vulnerability by this module
    itself -- per the roadmap's own instruction, this is endpoint
    *evidence* for a higher-level validator/Judge to interpret, not a
    finding.
    """

    candidate_url: str
    declared_method: str
    observations: list[EndpointObservation] = field(default_factory=list)
    blocked: bool = False
    block_reason: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "candidate_url": self.candidate_url,
            "declared_method": self.declared_method,
            "observations": [observation.to_dict() for observation in self.observations],
            "blocked": self.blocked,
            "block_reason": self.block_reason,
        }


async def validate_endpoint(
    url: str,
    declared_method: str,
    policy: PolicyEngine,
    timeout_seconds: float = 10.0,
    transport: httpx.AsyncBaseTransport | None = None,
) -> EndpointValidationEvidence:
    """P4.1-B: probes one endpoint candidate with only safe HTTP methods
    and records normalized, deterministic observations (status code,
    content-type, redirect chain) -- never a raw response body, and
    never a vulnerability verdict.

    Policy before execution: the candidate URL itself is checked before
    any request is sent, and every redirect hop is independently
    re-checked via policy.validate_redirect() before being followed --
    an out-of-scope redirect target stops the chain and is recorded,
    never fetched (the same record-only principle live/discovery.py's
    crawler already applies to links it won't follow).
    """
    decision = policy.validate_url(url)
    if not decision.allowed:
        return EndpointValidationEvidence(
            candidate_url=url, declared_method=declared_method, blocked=True, block_reason=decision.reason
        )

    observations = []
    async with httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=False, transport=transport) as client:
        for probe_method in normalize_probe_methods(declared_method):
            observations.append(await _probe_one(client, url, probe_method, policy))

    return EndpointValidationEvidence(candidate_url=url, declared_method=declared_method, observations=observations)


async def _probe_one(client: httpx.AsyncClient, url: str, method: str, policy: PolicyEngine) -> EndpointObservation:
    current_url = url
    redirect_chain: list[str] = []

    for _ in range(_MAX_REDIRECT_HOPS):
        try:
            response = await client.request(method, current_url)
        except httpx.HTTPError as exc:
            return EndpointObservation(method=method, status_code=None, content_type=None, redirect_chain=redirect_chain, error=str(exc))

        if response.status_code not in _REDIRECT_STATUS_CODES or "location" not in response.headers:
            return EndpointObservation(
                method=method,
                status_code=response.status_code,
                content_type=response.headers.get("content-type"),
                redirect_chain=redirect_chain,
            )

        next_url = urljoin(current_url, response.headers["location"])
        redirect_decision = policy.validate_redirect(current_url, next_url)
        redirect_chain.append(next_url)
        if not redirect_decision.allowed:
            return EndpointObservation(
                method=method,
                status_code=response.status_code,
                content_type=response.headers.get("content-type"),
                redirect_chain=redirect_chain,
                error=f"redirect target out of scope, not followed: {next_url}",
            )
        current_url = next_url

    return EndpointObservation(
        method=method, status_code=None, content_type=None, redirect_chain=redirect_chain, error="max redirect hops exceeded"
    )


@dataclass(frozen=True)
class PlannedRequest:
    """What *would* be sent for a state-changing request the method gate
    didn't allow -- recorded instead of sent. Body field names only,
    never values."""

    method: str
    url: str
    body_format: str
    body_fields: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {"method": self.method, "url": self.url, "body_format": self.body_format, "body_fields": list(self.body_fields)}


@dataclass(frozen=True)
class RequestValidationEvidence:
    """P4.5 WP-01: evidence for one EndpointSpec-driven request.
    `execution_mode` is the method gate's verdict -- "execute",
    "dry_run", "review_required" or "block" -- so a report can always
    tell "sent and observed" apart from "planned but deliberately not
    sent"."""

    candidate_url: str
    method: str
    risk: str
    execution_mode: str
    reason: str
    observation: EndpointObservation | None = None
    planned_request: PlannedRequest | None = None

    @property
    def status(self) -> ValidationStatus:
        if self.execution_mode == "block":
            return ValidationStatus.BLOCKED
        if self.execution_mode in {"dry_run", "review_required"}:
            return ValidationStatus.REVIEW_ONLY
        if self.observation is None or self.observation.status_code is None:
            return ValidationStatus.UNSTABLE
        return ValidationStatus.CONFIRMED

    def to_dict(self) -> dict[str, object]:
        return {
            "candidate_url": self.candidate_url,
            "method": self.method,
            "risk": self.risk,
            "execution_mode": self.execution_mode,
            "reason": self.reason,
            "observation": self.observation.to_dict() if self.observation else None,
            "planned_request": self.planned_request.to_dict() if self.planned_request else None,
            "status": self.status.value,
        }


def _encode_body(body_format: str, body: dict[str, object] | None) -> dict[str, object]:
    if body is None or body_format == "none":
        return {}
    if body_format == "json":
        return {"json": body}
    # multipart/form: sent as form fields only -- this validator never
    # fabricates file uploads.
    return {"data": {key: str(value) for key, value in body.items()}}


async def validate_endpoint_request(
    url: str,
    method: str,
    policy: PolicyEngine,
    body_format: str = "none",
    body_fields: list[str] | None = None,
    example_body: dict[str, object] | None = None,
    headers: dict[str, str] | None = None,
    timeout_seconds: float = 10.0,
    transport: httpx.AsyncBaseTransport | None = None,
) -> RequestValidationEvidence:
    """P4.5 WP-01 (v5.0 plan 5.1): sends one request with the spec's own
    method -- including POST/PUT/PATCH/DELETE -- but only once the
    common gate (scope, then PolicyEngine.decide_method) says "execute".

    A state-changing request is additionally never sent with a
    synthesized body: it needs a captured or user-supplied example body
    ("자동 검증은 기본적으로 무해한 파라미터 변경과 비교 요청에 제한"), otherwise it
    stays review_required. Redirects are not followed for state-changing
    methods (a 307/308 would replay the body elsewhere).
    """
    normalized = method.strip().upper()
    risk = method_risk(normalized)
    scope_decision = policy.validate_url(url)
    if not scope_decision.allowed:
        return RequestValidationEvidence(url, normalized, risk, "block", scope_decision.reason)

    planned = PlannedRequest(normalized, url, body_format, list(body_fields or []))
    method_decision = policy.decide_method(normalized)
    if not method_decision.allowed:
        return RequestValidationEvidence(
            url, normalized, risk, method_decision.mode, method_decision.reason, planned_request=planned
        )

    if risk == "read_only":
        async with httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=False, transport=transport) as client:
            observation = await _probe_one(client, url, normalized, policy)
        return RequestValidationEvidence(url, normalized, risk, "execute", method_decision.reason, observation=observation)

    if body_format != "none" and example_body is None:
        return RequestValidationEvidence(
            url, normalized, risk, "review_required",
            "no captured or user-supplied example body; a state-changing body is never synthesized",
            planned_request=planned,
        )

    async with httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=False, transport=transport) as client:
        try:
            response = await client.request(normalized, url, headers=headers, **_encode_body(body_format, example_body))
            observation = EndpointObservation(
                method=normalized, status_code=response.status_code, content_type=response.headers.get("content-type")
            )
        except httpx.HTTPError as exc:
            observation = EndpointObservation(method=normalized, status_code=None, content_type=None, error=str(exc))
    return RequestValidationEvidence(url, normalized, risk, "execute", method_decision.reason, observation=observation)
