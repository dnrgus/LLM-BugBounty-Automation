from __future__ import annotations

import json
from typing import Any

from adapters.scanner.nuclei import NucleiAdapter
from tools.runner import ExternalTool


def _build_command(target: str) -> list[str]:
    return ["nuclei", "-u", target, "-jsonl", "-silent"]


def _parse_output(stdout: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in stdout.splitlines() if line.strip()]


NUCLEI_TOOL = ExternalTool(
    id="nuclei",
    binary="nuclei",
    build_command=_build_command,
    parse_output=_parse_output,
    normalizer=NucleiAdapter(),
)
