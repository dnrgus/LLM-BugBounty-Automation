from __future__ import annotations

from dataclasses import dataclass
from typing import Literal
from uuid import uuid4

import httpx

from scope.policy import PolicyEngine
from validation.contract import ValidationStatus

InjectionLocation = Literal["query", "cookie", "header"]

# P4.1-D (roadmap v4.1.0 Dynamic Validation Expansion): sink categories
# this validator never actively probes -- matches
# validation/planner.py's _DESTRUCTIVE_SINK_TYPES, plus
# prompt_injection_sink (which already has a real executor via the llm
# capability hint's testcase_suite pack path, not this one) and ssrf/
# sql_injection (observable side effects would require actually
# exploiting the sink to detect, which this validator does not do).
_UNSAFE_TO_PROBE_SINK_TYPES = {
    "os_command",
    "deserialization",
    "code_execution",
    "file_access",
    "template_injection",
    "sql_injection",
    "ssrf",
    "prompt_injection_sink",
}

# Only sources reachable via a safe GET request (query string, cookie,
# header) can be exercised here -- form/json-bodied sources would need
# a body-carrying method, which this project never sends automatically.
_SAFE_INJECTION_LOCATIONS: frozenset[InjectionLocation] = frozenset({"query", "cookie", "header"})


def generate_correlation_token() -> str:
    """A unique, harmless marker -- never the value an attacker would
    actually use. Detecting whether *this* reaches an observable point
    is the whole mechanism; the sink is never actually triggered."""
    return f"DFCANARY-{uuid4().hex[:12]}"


def can_safely_probe(sink_type: str, injection_location: str) -> tuple[bool, str | None]:
    if sink_type in _UNSAFE_TO_PROBE_SINK_TYPES:
        return False, f"sink category {sink_type!r} is not safe to actively probe -- review_only"
    if injection_location not in _SAFE_INJECTION_LOCATIONS:
        return False, f"injection location {injection_location!r} requires a request body, which this validator never sends"
    return True, None


@dataclass(frozen=True)
class DataflowInjectionPoint:
    location: InjectionLocation
    name: str


@dataclass(frozen=True)
class DataflowCorrelationEvidence:
    """static_source_ref (the P3.2-3 DataEdge's own file:line) and the
    runtime observation below are deliberately kept as separate fields
    rather than merged into one -- per the roadmap's own instruction,
    "static path와 runtime observation을 서로 다른 evidence로 보존한다".
    """

    sink_type: str
    token: str
    static_source_ref: str
    injected: bool
    reflected_in_response: bool
    status_code: int | None
    blocked: bool = False
    block_reason: str | None = None
    skipped_reason: str | None = None

    @property
    def status(self) -> ValidationStatus:
        if self.blocked:
            return ValidationStatus.BLOCKED
        if self.skipped_reason:
            return ValidationStatus.REVIEW_ONLY
        if not self.injected:
            return ValidationStatus.UNSTABLE
        # Reflection only proves the token reached *some* observable
        # point, not that it reached the specific sink the static
        # analysis traced -- that correlation gap is exactly why a
        # reflection is review_only, never an automatic confirmation.
        return ValidationStatus.REVIEW_ONLY if self.reflected_in_response else ValidationStatus.REJECTED

    def to_dict(self) -> dict[str, object]:
        return {
            "sink_type": self.sink_type,
            "token": self.token,
            "static_source_ref": self.static_source_ref,
            "injected": self.injected,
            "reflected_in_response": self.reflected_in_response,
            "status_code": self.status_code,
            "blocked": self.blocked,
            "block_reason": self.block_reason,
            "skipped_reason": self.skipped_reason,
            "status": self.status.value,
        }


async def validate_dataflow_correlation(
    url: str,
    sink_type: str,
    injection: DataflowInjectionPoint,
    static_source_ref: str,
    policy: PolicyEngine,
    timeout_seconds: float = 10.0,
    transport: httpx.AsyncBaseTransport | None = None,
) -> DataflowCorrelationEvidence:
    """P4.1-D: connects a static P3.2-3 dataflow candidate to a runtime
    correlation check -- does a harmless token injected at the traced
    source come back observable at all -- instead of confirming
    anything from the static path alone. Never sends the sink's actual
    payload; never triggers the sink's real behavior.
    """
    can_probe, skip_reason = can_safely_probe(sink_type, injection.location)
    token = generate_correlation_token()
    if not can_probe:
        return DataflowCorrelationEvidence(
            sink_type=sink_type, token=token, static_source_ref=static_source_ref,
            injected=False, reflected_in_response=False, status_code=None, skipped_reason=skip_reason,
        )

    decision = policy.validate_url(url)
    if not decision.allowed:
        return DataflowCorrelationEvidence(
            sink_type=sink_type, token=token, static_source_ref=static_source_ref,
            injected=False, reflected_in_response=False, status_code=None, blocked=True, block_reason=decision.reason,
        )

    params: dict[str, str] = {}
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}
    if injection.location == "query":
        params[injection.name] = token
    elif injection.location == "header":
        headers[injection.name] = token
    else:
        cookies[injection.name] = token

    async with httpx.AsyncClient(
        timeout=timeout_seconds, follow_redirects=False, transport=transport, cookies=cookies
    ) as client:
        try:
            response = await client.get(url, params=params, headers=headers)
        except httpx.HTTPError as exc:
            return DataflowCorrelationEvidence(
                sink_type=sink_type, token=token, static_source_ref=static_source_ref,
                injected=True, reflected_in_response=False, status_code=None, skipped_reason=f"network error: {exc}",
            )

    reflected = token in response.text or token in str(response.headers)
    return DataflowCorrelationEvidence(
        sink_type=sink_type,
        token=token,
        static_source_ref=static_source_ref,
        injected=True,
        reflected_in_response=reflected,
        status_code=response.status_code,
    )
