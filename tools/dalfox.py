from __future__ import annotations

import json
from typing import Any, Callable

from tools.adapters.scanner.dalfox import DalfoxAdapter
from tools.runner import ExternalScanOptions, ExternalTool


def _command_builder(headers: dict[str, str]) -> Callable[[str], list[str]]:
    def build(target: str) -> list[str]:
        command = ["dalfox", "url", target, "--format", "json", "--silence"]
        for name, value in headers.items():
            command += ["--header", f"{name}: {value}"]
        return command

    return build


def _parse_output(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    data = json.loads(stdout)
    return data if isinstance(data, list) else (data.get("results") or data.get("findings") or [])


def make_dalfox_tool(options: ExternalScanOptions | None = None) -> ExternalTool:
    options = options or ExternalScanOptions()
    return ExternalTool(
        id="dalfox",
        binary="dalfox",
        build_command=_command_builder(options.auth_headers),
        parse_output=_parse_output,
        normalizer=DalfoxAdapter(),
    )


# Default no-auth argv builder, kept as a module-level name for backward
# compatibility with callers/tests that used it directly.
_build_command = _command_builder({})

# Default tool (no auth): preserves original behavior for callers that don't
# build one from ExternalScanOptions.
DALFOX_TOOL = make_dalfox_tool()
