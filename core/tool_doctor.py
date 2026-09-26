from __future__ import annotations

import platform
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from shutil import which
from typing import Any

import yaml

from core.paths import internal_dir


@dataclass(frozen=True)
class ToolStatus:
    name: str
    available: bool
    path: str | None
    version: str | None
    status: str
    category: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def load_tool_config(path: Path | str) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def check_tools(config_path: Path | str = "config/tools.yaml") -> dict[str, object]:
    config = load_tool_config(config_path)
    configured = config.get("tools", {})
    tools = []
    for name, tool_config in configured.items():
        if not tool_config.get("enabled", True):
            continue
        tools.append(check_tool(name, category=tool_config.get("category")))
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "tools": [tool.to_dict() for tool in tools],
    }


def check_tool(name: str, category: str | None = None) -> ToolStatus:
    tool_path = which(name)
    if tool_path is None:
        return ToolStatus(name=name, available=False, path=None, version=None, status="warn", category=category)
    version = detect_version(name)
    return ToolStatus(name=name, available=True, path=tool_path, version=version, status="ok", category=category)


def detect_version(name: str) -> str | None:
    commands = ([name, "--version"], [name, "version"], [name, "-version"])
    for command in commands:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
        except Exception:
            continue
        output = (result.stdout or result.stderr).strip()
        if output:
            return output.splitlines()[0]
    return None


def write_tool_lock(snapshot: dict[str, object], path: Path | str | None = None) -> Path:
    lock_path = Path(path) if path is not None else internal_dir("tool_versions.lock.yaml")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(yaml.safe_dump(snapshot, sort_keys=True), encoding="utf-8")
    return lock_path
