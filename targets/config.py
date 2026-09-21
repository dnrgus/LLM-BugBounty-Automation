from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from manifest.loader import build_manifest_target
from targets.base import TargetAdapter
from targets.http_target import CustomHTTPAdapter, CustomHTTPConfig, HTTPTargetConfig, OpenAICompatibleTarget

_SUPPORTED_ADAPTERS = {"openai_compatible", "custom_http", "universal"}


def _resolve_auth_header(auth: dict[str, Any]) -> dict[str, str]:
    api_key_env = auth.get("api_key_env")
    if not api_key_env:
        return {}
    api_key = os.environ.get(str(api_key_env))
    if not api_key:
        raise RuntimeError(f"{api_key_env} is not set; export it (see .env.example) before using this target config")
    header_name = str(auth.get("header_name", "Authorization"))
    header_prefix = str(auth.get("header_prefix", "Bearer "))
    return {header_name: f"{header_prefix}{api_key}"}


def load_target(path: Path | str) -> TargetAdapter:
    """Builds a TargetAdapter from a YAML target config file.

    See config/targets/*.example.yaml for the schema. Secrets are never
    read from the file itself -- `auth.api_key_env` names an environment
    variable (set in your shell or a gitignored .env) that holds the
    actual key/token.
    """
    with Path(path).open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    target = data.get("target") or {}

    adapter_kind = target.get("adapter")
    if adapter_kind not in _SUPPORTED_ADAPTERS:
        raise ValueError(
            f"unsupported adapter '{adapter_kind}' in {path}; expected one of {sorted(_SUPPORTED_ADAPTERS)}"
        )
    if "base_url" not in target:
        raise ValueError(f"target config {path} is missing required field 'base_url'")

    if adapter_kind == "universal":
        # U10 Universal Manifest: a richer, differently-shaped schema
        # (auth/interaction/session sections) -- resolved entirely by
        # manifest.loader rather than this function's
        # openai_compatible/custom_http-specific headers/auth handling.
        return build_manifest_target(target)

    headers: dict[str, str] = {"Content-Type": "application/json"}
    headers.update(_resolve_auth_header(target.get("auth") or {}))
    headers.update(target.get("headers") or {})

    target_id = str(target.get("id", adapter_kind))
    base_url = str(target["base_url"])
    timeout_seconds = float(target.get("timeout_seconds", 30.0))
    capabilities = dict(target.get("capabilities") or {"chat": True})

    if adapter_kind == "openai_compatible":
        model = str(target.get("model", "gpt-4o-mini"))
        return OpenAICompatibleTarget(
            HTTPTargetConfig(
                id=target_id,
                kind="llm",
                provider="openai-compatible",
                name=model,
                version=model,
                base_url=base_url,
                headers=headers,
                timeout_seconds=timeout_seconds,
                capabilities=capabilities,
            )
        )

    request = target.get("request") or {}
    return CustomHTTPAdapter(
        CustomHTTPConfig(
            id=target_id,
            kind="llm",
            provider="custom-http",
            name=target_id,
            version=str(target.get("version", "unknown")),
            base_url=base_url,
            request_path=str(request.get("path", "")),
            method=str(request.get("method", "POST")),
            request_body_template=request.get("body_template") or {"message": "{{PROMPT}}"},
            response_text_path=str(request.get("response_text_path", "response")),
            headers=headers,
            timeout_seconds=timeout_seconds,
            capabilities=capabilities,
        )
    )
