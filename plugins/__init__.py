"""U12 Browser Plugin SDK: a target-adapter plugin registry
(adapter: <name> in target.yaml -> a builder, without touching
targets/config.py), plus the optional Playwright-based "browser" plugin.
"""

from plugins.registry import get_plugin, register_plugin, registered_plugin_names

from plugins import browser as _browser  # noqa: F401 -- import registers the "browser" plugin

__all__ = ["get_plugin", "register_plugin", "registered_plugin_names"]
