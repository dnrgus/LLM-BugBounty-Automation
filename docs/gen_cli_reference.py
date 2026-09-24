"""Regenerates docs/CLI.md from the argparse parser: `python docs/gen_cli_reference.py`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cli import build_parser  # noqa: E402
from core.contract import EXIT_CODES, FINDING_STATES  # noqa: E402


def render() -> str:
    parser = build_parser()
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    help_by_name = {choice.dest: choice.help for choice in sub._choices_actions}
    lines = [
        "# CLI Reference (v5.0)", "",
        "Generated from `cli.build_parser()`; `tests/test_v5_contract.py` fails if a command or option is missing here.", "",
        "## Exit codes", "", "| code | meaning |", "|---|---|",
    ]
    lines += [f"| {code} | {meaning} |" for code, meaning in EXIT_CODES.items()]
    lines += ["", "## Finding states", "", "| state | meaning |", "|---|---|"]
    lines += [f"| `{state}` | {meaning} |" for state, meaning in FINDING_STATES.items()]
    lines += ["", "## Commands", ""]
    for name, subparser in sub.choices.items():
        lines += [f"### `{name}`", "", (help_by_name.get(name) or "").strip(), ""]
        for action in subparser._actions:
            if isinstance(action, argparse._HelpAction):
                continue
            flag = ", ".join(action.option_strings) if action.option_strings else action.dest
            default = "" if action.default in (None, argparse.SUPPRESS, False) or action.required else f" (default: `{action.default}`)"
            required = " **required**" if getattr(action, "required", False) and action.option_strings else ""
            help_text = (action.help or "").replace("\n", " ").replace("|", "\\|")
            lines.append(f"- `{flag}`{required}{default} — {help_text}".rstrip(" —"))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


if __name__ == "__main__":
    (Path(__file__).resolve().parent / "CLI.md").write_text(render(), encoding="utf-8")
