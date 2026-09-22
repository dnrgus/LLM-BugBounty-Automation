from __future__ import annotations

import json
from typing import Any

from adapters.scanner.dalfox import DalfoxAdapter
from tools.runner import ExternalTool


def _build_command(target: str) -> list[str]:
    return ["dalfox", "url", target, "--format", "json", "--silence"]


def _parse_output(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    data = json.loads(stdout)
    return data if isinstance(data, list) else (data.get("results") or data.get("findings") or [])


DALFOX_TOOL = ExternalTool(
    id="dalfox",
    binary="dalfox",
    build_command=_build_command,
    parse_output=_parse_output,
    normalizer=DalfoxAdapter(),
)
