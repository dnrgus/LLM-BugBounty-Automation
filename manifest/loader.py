from __future__ import annotations

from typing import Any

from manifest.adapter import CompatibilityAdapter, ManifestTargetConfig
from manifest.auth import build_auth
from manifest.interaction import build_interaction
from manifest.session import build_session_policy


def build_manifest_target(target: dict[str, Any]) -> CompatibilityAdapter:
    """Builds a CompatibilityAdapter from a target.yaml `target:` block
    using the U10 "universal" schema (auth/interaction/session sections),
    as dispatched by targets/config.py's load_target() for
    `adapter: universal`. See config/targets/*.example.yaml for the
    existing openai_compatible/custom_http schema this is additive to.
    """
    if "base_url" not in target:
        raise ValueError("target manifest is missing required field 'base_url'")

    return CompatibilityAdapter(
        ManifestTargetConfig(
            id=str(target.get("id", "universal")),
            name=str(target.get("name", target.get("id", "universal"))),
            version=str(target.get("version", "unknown")),
            base_url=str(target["base_url"]),
            auth=build_auth(target.get("auth") or {}),
            interaction=build_interaction(target.get("interaction") or {}),
            session_policy=build_session_policy(target.get("session") or {}),
            capabilities=dict(target.get("capabilities") or {"chat": True}),
            timeout_seconds=float(target.get("timeout_seconds", 30.0)),
            extra_headers=dict(target.get("headers") or {}),
        )
    )
