"""P4.2-C NestJS decorator classification (roadmap v4.2.0 Source
Intelligence Expansion) -- pure logic, no tree-sitter dependency."""

from source.frameworks.nestjs import http_method_for_decorator, is_controller_decorator, join_route_path


def test_http_method_for_decorator_maps_known_names() -> None:
    assert http_method_for_decorator("Get") == "GET"
    assert http_method_for_decorator("Post") == "POST"
    assert http_method_for_decorator("Delete") == "DELETE"
    assert http_method_for_decorator("All") == "ANY"


def test_http_method_for_decorator_rejects_unrelated_names() -> None:
    assert http_method_for_decorator("UseGuards") is None
    assert http_method_for_decorator("Injectable") is None


def test_is_controller_decorator() -> None:
    assert is_controller_decorator("Controller") is True
    assert is_controller_decorator("Injectable") is False


def test_join_route_path_combines_prefix_and_method_path() -> None:
    assert join_route_path("cats", ":id") == "/cats/:id"


def test_join_route_path_handles_empty_prefix_and_path() -> None:
    assert join_route_path("", "") == "/"
    assert join_route_path("cats", "") == "/cats"
    assert join_route_path("", ":id") == "/:id"


def test_join_route_path_strips_extra_slashes() -> None:
    assert join_route_path("/cats/", "/:id/") == "/cats/:id"
