from __future__ import annotations

import json
from typing import Any

from tools.adapters.secrets.trufflehog import TruffleHogAdapter
from tools.runner import ExternalTool


def _build_command(path: str) -> list[str]:
    return ["trufflehog", "filesystem", path, "--json"]


def _parse_output(stdout: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in stdout.splitlines() if line.strip()]


# Status: planned -- defined here but not wired into the default scan or
# any Pack yet (nothing imports it).
# Filesystem-scan mode only (not a URL fetch -- TruffleHog itself has no
# "scan this single URL" mode). Callers with a local path (e.g. a
# downloaded page/JS bundle) can run this directly; wiring it into a live
# URL-based Pack requires fetching content to disk first, left for a
# later phase rather than guessing an invocation TruffleHog doesn't have.
TRUFFLEHOG_FILESYSTEM_TOOL = ExternalTool(
    id="trufflehog",
    binary="trufflehog",
    build_command=_build_command,
    parse_output=_parse_output,
    normalizer=TruffleHogAdapter(),
)
