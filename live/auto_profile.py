from __future__ import annotations

from dataclasses import asdict, dataclass

import httpx

from core.models import Run, Target
from core.profiler import TargetProfile, profile_target
from executor.runner import Executor
from live.classify import ClassifiedCandidate
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from targets.http_target import CustomHTTPAdapter, CustomHTTPConfig

# Discovery is black-box: the request/response JSON schema of an
# auto-discovered endpoint is never actually known ahead of time. This is a
# short list of common shapes tried in order; the first one that produces a
# plausible response wins. This is a best-effort guess, not a claim of
# certainty -- callers should treat a failed auto-profile as "unknown", not
# as "not an LLM endpoint".
_GUESSED_REQUEST_SHAPES: list[tuple[dict[str, object], str]] = [
    ({"message": "{{PROMPT}}"}, "response"),
    ({"prompt": "{{PROMPT}}"}, "text"),
    ({"input": "{{PROMPT}}"}, "output"),
    ({"messages": [{"role": "user", "content": "{{PROMPT}}"}]}, "choices.0.message.content"),
]


@dataclass
class AutoProfileResult:
    candidate: ClassifiedCandidate
    attempted: bool
    profile: TargetProfile | None
    guessed_schema: dict[str, object] | None
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "location": self.candidate.location,
            "kind": self.candidate.kind,
            "attempted": self.attempted,
            "guessed_schema": self.guessed_schema,
            "profile": self.profile.to_dict() if self.profile else None,
            "error": self.error,
        }


async def auto_profile_candidates(
    candidates: list[ClassifiedCandidate],
    policy: PolicyEngine,
    store: SQLiteStore,
    transport: httpx.AsyncBaseTransport | None = None,
) -> list[AutoProfileResult]:
    """U5 "probe 연결" (design doc section 7): hands classified llm/api
    candidates that resolve to a concrete endpoint URL off to the existing
    Capability Probe (core/profiler.py) for real verification, instead of
    inventing new ad-hoc probing logic.

    Every probe request still goes through Executor.execute(), so it is
    subject to the same Scope/Policy check as any other request -- "Policy
    Before Request" applies here exactly as it does to attack testcases.
    """
    store.initialize()
    results: list[AutoProfileResult] = []
    for candidate in candidates:
        if candidate.kind not in {"llm", "api"}:
            continue
        if not candidate.location.startswith(("http://", "https://")):
            continue
        results.append(await _try_profile(candidate, policy, store, transport))
    return results


async def _try_profile(
    candidate: ClassifiedCandidate,
    policy: PolicyEngine,
    store: SQLiteStore,
    transport: httpx.AsyncBaseTransport | None,
) -> AutoProfileResult:
    # "Policy Before Request" applies even though candidate.location was
    # already scope-checked once by discover_target() -- this module must
    # not assume its caller preserved that invariant, so it re-validates
    # independently before target.healthcheck() (which, unlike
    # Executor.execute(), does not go through the policy engine itself).
    decision = policy.validate_url(candidate.location)
    if not decision.allowed:
        return AutoProfileResult(
            candidate=candidate, attempted=False, profile=None, guessed_schema=None,
            error=f"blocked by scope/policy: {decision.reason}",
        )

    # CustomHTTPAdapter.metadata() reports f"{base_url.rstrip('/')}{request_path}".
    # If candidate.location itself ends in "/" and request_path is left empty,
    # that reconstruction silently drops the trailing slash -- a different
    # string than the one just validated above, which can make the
    # *executor's own* scope check spuriously reject an already-approved URL.
    # Splitting off the trailing slashes into request_path keeps the
    # reconstructed URL identical to candidate.location.
    stripped_location = candidate.location.rstrip("/")
    trailing_slashes = candidate.location[len(stripped_location) :]

    last_error: str | None = None
    for attempt_number, (body_template, response_path) in enumerate(_GUESSED_REQUEST_SHAPES, start=1):
        target_id = f"auto-{candidate.source_item.id}-{attempt_number}"
        adapter = CustomHTTPAdapter(
            CustomHTTPConfig(
                id=target_id,
                kind="llm",
                provider="auto-discovered",
                name=candidate.location,
                version="unknown",
                base_url=candidate.location,
                request_path=trailing_slashes,
                method="POST",
                request_body_template=body_template,
                response_text_path=response_path,
                transport=transport,
            )
        )
        target_metadata = await adapter.metadata()
        capabilities = await adapter.capabilities()
        run = Run(target_id=target_metadata.id, policy_hash=policy.policy_hash, fingerprint="auto-profile")
        store.insert_target(
            Target(
                id=target_metadata.id,
                kind=target_metadata.kind,
                base_url=target_metadata.base_url,
                capabilities=capabilities.to_dict(),
                metadata=asdict(target_metadata),
            )
        )
        store.insert_run(run)
        executor = Executor(policy=policy, target=adapter, store=store, target_id=target_metadata.id)

        try:
            profile = await profile_target(executor, adapter, run, store, probe=True)
        except PermissionError as exc:
            return AutoProfileResult(
                candidate=candidate, attempted=False, profile=None, guessed_schema=None,
                error=f"blocked by scope/policy: {exc}",
            )
        except Exception as exc:  # noqa: BLE001 -- a wrong guessed schema surfaces as an arbitrary target/parse error
            last_error = str(exc)
            continue

        if profile.reachable and profile.probe_response_sample:
            return AutoProfileResult(
                candidate=candidate, attempted=True, profile=profile,
                guessed_schema={"body": body_template, "response_text_path": response_path},
            )
        last_error = "; ".join(profile.notes) or "no response sample"

    return AutoProfileResult(candidate=candidate, attempted=True, profile=None, guessed_schema=None, error=last_error)
