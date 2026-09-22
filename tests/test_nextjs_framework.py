from pathlib import Path

from source.frameworks.nextjs import (
    app_router_route_path,
    is_app_router_route_file,
    is_pages_api_route,
    pages_api_route_path,
)


def test_is_pages_api_route_detects_pages_api_directory() -> None:
    assert is_pages_api_route(Path("/repo/pages/api/users.js")) is True
    assert is_pages_api_route(Path("/repo/pages/about.js")) is False
    assert is_pages_api_route(Path("/repo/src/other.js")) is False


def test_pages_api_route_path_converts_dynamic_segments() -> None:
    assert pages_api_route_path(Path("/repo/pages/api/users/[id].js")) == "/api/users/:id"
    assert pages_api_route_path(Path("/repo/pages/api/users/index.js")) == "/api/users"
    assert pages_api_route_path(Path("/repo/pages/api/files/[...slug].js")) == "/api/files/*slug"


def test_is_app_router_route_file_requires_app_dir_and_route_filename() -> None:
    assert is_app_router_route_file(Path("/repo/app/api/users/route.ts")) is True
    assert is_app_router_route_file(Path("/repo/app/api/users/handler.ts")) is False
    assert is_app_router_route_file(Path("/repo/pages/api/users/route.ts")) is False


def test_app_router_route_path_drops_route_groups_and_converts_segments() -> None:
    assert app_router_route_path(Path("/repo/app/api/users/[id]/route.ts")) == "/api/users/:id"
    assert app_router_route_path(Path("/repo/app/(marketing)/api/ping/route.ts")) == "/api/ping"
