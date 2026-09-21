from __future__ import annotations

from importlib import metadata
from typing import Any, Callable

from targets.base import TargetAdapter

TargetAdapterBuilder = Callable[[dict[str, Any]], TargetAdapter]

_ENTRY_POINT_GROUP = "llmbb.target_adapters"

_registry: dict[str, TargetAdapterBuilder] = {}


def register_plugin(name: str, builder: TargetAdapterBuilder) -> None:
    """Registers a TargetAdapter builder under `name`, making it usable
    as `adapter: <name>` in target.yaml without ever touching
    targets/config.py's hardcoded dispatch. A third-party package can do
    the same by registering a `llmbb.target_adapters` entry point instead
    of depending on this module directly.
    """
    _registry[name] = builder


def get_plugin(name: str | None) -> TargetAdapterBuilder | None:
    if not name:
        return None
    if name in _registry:
        return _registry[name]
    for entry_point in metadata.entry_points(group=_ENTRY_POINT_GROUP):
        if entry_point.name == name:
            return entry_point.load()
    return None


def registered_plugin_names() -> list[str]:
    names = set(_registry)
    names.update(entry_point.name for entry_point in metadata.entry_points(group=_ENTRY_POINT_GROUP))
    return sorted(names)
