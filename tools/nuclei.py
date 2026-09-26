from __future__ import annotations

import json
from typing import Any, Callable

from tools.adapters.scanner.nuclei import NucleiAdapter
from tools.runner import ExternalScanOptions, ExternalTool


def _parse_output(stdout: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in stdout.splitlines() if line.strip()]


def _command_builder(
    headers: dict[str, str], dast: bool, full_templates: bool, target_list: str | None = None
) -> Callable[[str], list[str]]:
    """Build a nuclei argv closure (WP-05/06).

    - headers: reused auth/session headers (§19), one -H per header.
    - dast: add -dast so nuclei's fuzzing templates run (parameter SQLi/XSS
      etc.), which is what actually found Juice Shop's SQLi (§7).
    - full_templates: without it, a dast scan restricts to the fuzzing
      (dast) template set for speed; with it, the full template set also
      runs. When dast is off this flag has no effect (default template run).
    - target_list: when set, scan every URL in this file (-l) instead of the
      single -u target -- used to fuzz the parameterized endpoints reused
      from discovery (§8). The -u target is still what Policy/Scope validated
      in run_external_tool; the list only ever contains URLs discovery
      already validated in-scope.
    """

    def build(target: str) -> list[str]:
        if target_list is not None:
            command = ["nuclei", "-l", target_list, "-jsonl", "-silent"]
        else:
            command = ["nuclei", "-u", target, "-jsonl", "-silent"]
        for name, value in headers.items():
            command += ["-H", f"{name}: {value}"]
        if dast:
            command.append("-dast")
            if not full_templates:
                command += ["-tags", "dast"]
        return command

    return build


def make_nuclei_tool(
    options: ExternalScanOptions | None = None, target_list: str | None = None
) -> ExternalTool:
    options = options or ExternalScanOptions()
    return ExternalTool(
        id="nuclei",
        binary="nuclei",
        build_command=_command_builder(
            options.auth_headers, options.nuclei_dast, options.full_templates, target_list
        ),
        parse_output=_parse_output,
        normalizer=NucleiAdapter(),
    )


# Default no-auth, no-DAST argv builder, kept as a module-level name for
# backward compatibility with callers/tests that used it directly.
_build_command = _command_builder({}, dast=False, full_templates=False)

# Default tool (no auth, no DAST): preserves the original behavior for any
# caller that doesn't build one from ExternalScanOptions.
NUCLEI_TOOL = make_nuclei_tool()
