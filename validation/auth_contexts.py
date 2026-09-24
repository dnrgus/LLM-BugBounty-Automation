from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from source.endpoints import EndpointSpec
from validation.auth_validator import AuthContext

# P4.5 WP-02 (v5.0 plan 5.2): the auth context model. Every context is a
# test account the tester registered themselves and declared in a YAML
# file -- this project never guesses, enumerates or obtains credentials.
# Credential material is only ever referenced by environment variable
# *name* in the file and resolved at load time; it never appears in
# to_dict(), evidence, or reports (AuthContext.to_dict already omits
# headers).

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

# Parameter names treated as object-identifier candidates.
_OBJECT_ID_NAME = re.compile(r"^(?i:id|uuid|guid|pk|slug)$|(?:_id|Id|ID|_uuid|Uuid|_pk)$")


@dataclass(frozen=True)
class TesterAccount:
    """One tester-owned account: its request context, its role, and the
    test objects it owns (param name -> value), e.g. {"note_id": "101"}."""

    __test__ = False  # not a pytest test class despite the name

    context: AuthContext
    role: str = "user"
    owned_objects: dict[str, str] = field(default_factory=dict)
    missing_env: list[str] = field(default_factory=list)

    @property
    def usable(self) -> bool:
        return not self.missing_env

    def to_dict(self) -> dict[str, object]:
        return {
            **self.context.to_dict(),
            "role": self.role,
            "owned_object_params": sorted(self.owned_objects),
            "usable": self.usable,
            "missing_env": list(self.missing_env),
        }


@dataclass(frozen=True)
class AuthContextSet:
    accounts: list[TesterAccount] = field(default_factory=list)

    def usable_accounts(self) -> list[TesterAccount]:
        return [account for account in self.accounts if account.usable and account.context.id != "anonymous"]

    def to_dict(self) -> dict[str, object]:
        return {"accounts": [account.to_dict() for account in self.accounts]}


def _resolve(value: str, missing: list[str]) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        resolved = os.environ.get(name)
        if resolved is None:
            missing.append(name)
            return ""
        return resolved

    return _ENV_REF.sub(replace, value)


def load_auth_contexts(path: Path | str) -> AuthContextSet:
    """YAML shape:

        accounts:
          - id: user_a
            role: user
            headers: {Authorization: "Bearer ${USER_A_TOKEN}"}
            owned_objects: {note_id: "101"}

    Literal header values are rejected -- a credential must come from an
    environment variable so it never lands in a committed file."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    accounts: list[TesterAccount] = []
    for entry in data.get("accounts", []):
        missing: list[str] = []
        headers: dict[str, str] = {}
        for name, raw in (entry.get("headers") or {}).items():
            raw = str(raw)
            if not _ENV_REF.search(raw):
                raise ValueError(
                    f"auth context {entry.get('id')!r}: header {name!r} must reference an environment variable (${{VAR}})"
                )
            headers[str(name)] = _resolve(raw, missing)
        context = AuthContext(
            id=str(entry["id"]),
            principal_label=str(entry.get("label", entry["id"])),
            credential_source="env",
            headers=headers,
        )
        accounts.append(
            TesterAccount(
                context=context,
                role=str(entry.get("role", "user")),
                owned_objects={str(k): str(v) for k, v in (entry.get("owned_objects") or {}).items()},
                missing_env=sorted(set(missing)),
            )
        )
    return AuthContextSet(accounts)


def object_id_candidates(spec: EndpointSpec) -> list[dict[str, str]]:
    """Object-identifier candidates in path/query/body, by name only."""
    candidates: list[dict[str, str]] = []
    for location, names in (("path", spec.path_params), ("query", spec.query_params), ("body", spec.body_fields)):
        for name in names:
            if _OBJECT_ID_NAME.search(name):
                candidates.append({"location": location, "name": name})
    return candidates
