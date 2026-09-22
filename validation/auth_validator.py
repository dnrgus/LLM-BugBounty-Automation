from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Literal

import httpx

from scope.policy import PolicyEngine
from validation.contract import ValidationStatus

CredentialSource = Literal["fixture", "env", "browser-session"]


@dataclass(frozen=True)
class AuthContext:
    """A logical principal to send a request as -- e.g. "anonymous",
    "session A", "session B" (roadmap's own examples). Safety scope
    (roadmap's own words): built only from an explicitly supplied
    fixture/env/browser-session credential -- this project never
    guesses, brute-forces, or takes over an account to construct one.

    `headers` deliberately never appears in to_dict(): the credential
    material itself (a bearer token, a session cookie) must never end
    up in evidence/report output, only the fact that *some* context
    with this label/source was used.
    """

    id: str
    principal_label: str
    session_ref: str | None = None
    credential_source: CredentialSource = "fixture"
    allowed_scope: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "principal_label": self.principal_label,
            "session_ref": self.session_ref,
            "credential_source": self.credential_source,
            "allowed_scope": list(self.allowed_scope),
        }


ANONYMOUS_CONTEXT = AuthContext(id="anonymous", principal_label="anonymous", credential_source="fixture")


def _body_shape(content_type: str | None, text: str) -> str | None:
    """A structural fingerprint of a response body -- sorted top-level
    JSON keys, or a coarse length bucket for anything else -- never the
    raw body itself, which could contain the very data an auth check is
    trying to protect."""
    if not text:
        return "empty"
    if content_type and "json" in content_type:
        try:
            parsed = json.loads(text)
        except ValueError:
            return f"invalid_json:{len(text)}"
        if isinstance(parsed, dict):
            return "json_keys:" + ",".join(sorted(parsed.keys()))
        if isinstance(parsed, list):
            return f"json_array:{len(parsed)}"
        return f"json_scalar:{type(parsed).__name__}"
    return f"non_json_length_bucket:{len(text) // 100}"


@dataclass(frozen=True)
class AuthObservation:
    context_id: str
    status_code: int | None
    content_type: str | None
    body_shape: str | None
    selected_fields: dict[str, object] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "context_id": self.context_id,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "body_shape": self.body_shape,
            "selected_fields": dict(self.selected_fields),
            "error": self.error,
        }


@dataclass(frozen=True)
class AuthComparison:
    control_context: str
    probe_context: str
    resource_key: str
    observations: list[AuthObservation] = field(default_factory=list)

    @property
    def status(self) -> ValidationStatus:
        """Never CONFIRMED on an ambiguous result -- the roadmap's own
        safety instruction for this validator. Only a clean, same-shape
        success on both sides (probe genuinely reached what control
        reached) confirms; probe being denied is a clean rejection;
        anything else (errors, a surprising asymmetry, differently
        shaped success) stays UNSTABLE/REVIEW_ONLY for a human to look
        at, never auto-escalated.
        """
        if len(self.observations) != 2:
            return ValidationStatus.REVIEW_ONLY
        control, probe = self.observations
        if control.error or probe.error:
            return ValidationStatus.UNSTABLE
        if control.status_code is None or probe.status_code is None:
            return ValidationStatus.UNSTABLE

        control_ok = 200 <= control.status_code < 300
        probe_ok = 200 <= probe.status_code < 300
        if control_ok and probe_ok and control.body_shape == probe.body_shape:
            return ValidationStatus.CONFIRMED
        if not probe_ok:
            return ValidationStatus.REJECTED
        if probe_ok and not control_ok:
            return ValidationStatus.UNSTABLE
        return ValidationStatus.REVIEW_ONLY

    def to_dict(self) -> dict[str, object]:
        return {
            "control_context": self.control_context,
            "probe_context": self.probe_context,
            "resource_key": self.resource_key,
            "observations": [observation.to_dict() for observation in self.observations],
            "status": self.status.value,
        }


async def compare_auth_contexts(
    url: str,
    method: str,
    control: AuthContext,
    probe: AuthContext,
    policy: PolicyEngine,
    resource_key: str | None = None,
    selected_fields: list[str] | None = None,
    timeout_seconds: float = 10.0,
    transport: httpx.AsyncBaseTransport | None = None,
) -> AuthComparison:
    """P4.1-C (roadmap v4.1.0 Dynamic Validation Expansion): sends the
    same safe request as two different AuthContexts and records
    normalized, comparable observations -- never a raw response body,
    always Policy-checked first.
    """
    decision = policy.validate_url(url)
    if not decision.allowed:
        return AuthComparison(control_context=control.id, probe_context=probe.id, resource_key=resource_key or url, observations=[])

    async with httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=False, transport=transport) as client:
        control_observation = await _probe_as(client, url, method, control, selected_fields)
        probe_observation = await _probe_as(client, url, method, probe, selected_fields)

    return AuthComparison(
        control_context=control.id,
        probe_context=probe.id,
        resource_key=resource_key or url,
        observations=[control_observation, probe_observation],
    )


async def _probe_as(
    client: httpx.AsyncClient, url: str, method: str, context: AuthContext, selected_fields: list[str] | None
) -> AuthObservation:
    try:
        response = await client.request(method, url, headers=context.headers)
    except httpx.HTTPError as exc:
        return AuthObservation(context_id=context.id, status_code=None, content_type=None, body_shape=None, error=str(exc))

    content_type = response.headers.get("content-type")
    fields: dict[str, object] = {}
    if selected_fields and content_type and "json" in content_type:
        try:
            parsed = json.loads(response.text)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            fields = {key: parsed[key] for key in selected_fields if key in parsed}

    return AuthObservation(
        context_id=context.id,
        status_code=response.status_code,
        content_type=content_type,
        body_shape=_body_shape(content_type, response.text),
        selected_fields=fields,
    )
