from plugins.registry import get_plugin, register_plugin, registered_plugin_names


def test_browser_plugin_is_registered_by_default() -> None:
    assert "browser" in registered_plugin_names()
    assert get_plugin("browser") is not None


def test_get_plugin_returns_none_for_unknown_name() -> None:
    assert get_plugin("does-not-exist") is None


def test_get_plugin_returns_none_for_empty_name() -> None:
    assert get_plugin(None) is None
    assert get_plugin("") is None


def test_register_plugin_makes_a_new_adapter_kind_available() -> None:
    def _builder(target: dict) -> str:
        return f"built:{target.get('id')}"

    register_plugin("test-custom-kind", _builder)
    try:
        assert "test-custom-kind" in registered_plugin_names()
        builder = get_plugin("test-custom-kind")
        assert builder is not None
        assert builder({"id": "t1"}) == "built:t1"
    finally:
        from plugins import registry

        registry._registry.pop("test-custom-kind", None)
