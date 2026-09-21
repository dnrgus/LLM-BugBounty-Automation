from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import Any, Protocol


class AuthProvider(Protocol):
    def headers(self) -> dict[str, str]: ...


@dataclass(frozen=True)
class NoAuth:
    def headers(self) -> dict[str, str]:
        return {}


@dataclass(frozen=True)
class BearerTokenAuth:
    api_key_env: str
    header_name: str = "Authorization"
    header_prefix: str = "Bearer "

    def headers(self) -> dict[str, str]:
        return {self.header_name: f"{self.header_prefix}{_require_env(self.api_key_env)}"}


@dataclass(frozen=True)
class ApiKeyHeaderAuth:
    api_key_env: str
    header_name: str = "X-API-Key"

    def headers(self) -> dict[str, str]:
        return {self.header_name: _require_env(self.api_key_env)}


@dataclass(frozen=True)
class BasicAuth:
    username_env: str
    password_env: str

    def headers(self) -> dict[str, str]:
        username = _require_env(self.username_env)
        password = _require_env(self.password_env)
        token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        return {"Authorization": f"Basic {token}"}


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is not set; export it (see .env.example) before using this target manifest")
    return value


def build_auth(config: dict[str, Any]) -> AuthProvider:
    auth_type = config.get("type", "none")
    if auth_type == "none":
        return NoAuth()
    if auth_type == "bearer":
        return BearerTokenAuth(
            api_key_env=config["api_key_env"],
            header_name=str(config.get("header_name", "Authorization")),
            header_prefix=str(config.get("header_prefix", "Bearer ")),
        )
    if auth_type == "api_key":
        return ApiKeyHeaderAuth(
            api_key_env=config["api_key_env"], header_name=str(config.get("header_name", "X-API-Key"))
        )
    if auth_type == "basic":
        return BasicAuth(username_env=config["username_env"], password_env=config["password_env"])
    raise ValueError(f"unsupported auth type: {auth_type}")
