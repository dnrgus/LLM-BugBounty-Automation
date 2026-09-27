from __future__ import annotations

import json
from typing import Any, Callable

from tools.adapters.discovery.katana import KatanaAdapter
from tools.runner import ExternalTool


def _parse_output(stdout: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in stdout.splitlines() if line.strip()]


def _command_builder(depth: int, headers: dict[str, str]) -> Callable[[str], list[str]]:
    """Build a katana argv closure.

    -hl (headless) + -xhr-extraction is what actually catches an SPA's
    fetch/XHR calls -- e.g. Juice Shop's product grid firing
    /rest/products/search?q= on page load, which a plain HTML link/form
    crawl (live.discovery.discover_target) never sees. -jc additionally
    mines endpoints referenced inside bundled JS.
    """

    def build(target: str) -> list[str]:
        command = [
            "katana", "-u", target,
            "-jc", "-hl", "-xhr-extraction",
            "-d", str(depth),
            "-jsonl", "-silent",
        ]
        for name, value in headers.items():
            command += ["-H", f"{name}: {value}"]
        return command

    return build


def make_katana_tool(depth: int = 2, headers: dict[str, str] | None = None) -> ExternalTool:
    return ExternalTool(
        id="katana",
        binary="katana",
        build_command=_command_builder(depth, headers or {}),
        parse_output=_parse_output,
        normalizer=KatanaAdapter(),
    )
