"""P3.2-2 JavaScript/TypeScript Parser (roadmap v3.2.0 Source Intelligence).

Requires the optional `jsts` extra (tree-sitter). Skips gracefully if it
is not installed, since it's an optional dependency (same pattern as the
browser adapter's Playwright dependency) -- source/routes.py's per-file
regex fallback is what actually runs in that case.
"""

from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")

from source.parsers.javascript import JavaScriptTypeScriptParser  # noqa: E402

_parser = JavaScriptTypeScriptParser()


def test_parses_express_get_route_with_named_handler() -> None:
    text = (
        "const app = require('express')();\n"
        "function chat(req, res) { res.send('ok'); }\n"
        "app.get('/api/chat', chat);\n"
    )
    result = _parser.parse_file(Path("app.js"), text)
    assert not result.errors
    assert len(result.routes) == 1
    route = result.routes[0]
    assert route.method == "GET"
    assert route.path == "/api/chat"
    assert route.handler == "chat"
    assert route.framework == "express"


def test_parses_express_post_route_with_inline_arrow_handler() -> None:
    text = "router.post('/api/admin/run', (req, res) => { res.send('ok'); });\n"
    result = _parser.parse_file(Path("routes.js"), text)
    assert len(result.routes) == 1
    assert result.routes[0].method == "POST"
    assert result.routes[0].path == "/api/admin/run"


def test_unrelated_get_calls_are_not_treated_as_express_routes() -> None:
    text = "const value = someMap.get('key');\n"
    result = _parser.parse_file(Path("util.js"), text)
    assert result.routes == []


def test_records_call_nodes_including_sink_like_calls() -> None:
    text = (
        "function run(cmd) {\n"
        "  child_process.exec(cmd);\n"
        "  db.query('select 1');\n"
        "}\n"
    )
    result = _parser.parse_file(Path("sink.js"), text)
    names = {call.name for call in result.calls}
    assert "child_process.exec" in names
    assert "db.query" in names
    exec_call = next(call for call in result.calls if call.name == "child_process.exec")
    assert exec_call.enclosing_function == "run"


def test_typescript_file_parses_with_type_annotations() -> None:
    text = "app.get('/health', (req: Request, res: Response): void => { res.send('ok'); });\n"
    result = _parser.parse_file(Path("app.ts"), text)
    assert not result.errors
    assert result.routes[0].method == "GET"
    assert result.routes[0].path == "/health"


def test_syntax_error_is_reported_as_a_parser_error() -> None:
    result = _parser.parse_file(Path("broken.js"), "function ( { [[[ syntax error\n")
    # tree-sitter is error-tolerant by design (it produces a partial tree
    # with ERROR nodes rather than raising) -- assert it never crashes and
    # never invents a route out of the garbage input, which is the
    # property source/routes.py's fallback logic actually depends on.
    assert result.routes == []


def test_nextjs_app_router_route_extracts_exported_http_methods() -> None:
    text = (
        "export async function GET(request) {\n"
        "  return Response.json({ ok: true });\n"
        "}\n"
        "export async function POST(request) {\n"
        "  return Response.json({ ok: true });\n"
        "}\n"
    )
    result = _parser.parse_file(Path("app/api/users/route.ts"), text)
    methods = {(route.method, route.path, route.handler) for route in result.routes}
    assert ("GET", "/api/users", "GET") in methods
    assert ("POST", "/api/users", "POST") in methods
    assert all(route.framework == "nextjs_app_router" for route in result.routes)


def test_nextjs_pages_router_route_reports_method_any() -> None:
    text = "export default function handler(req, res) {\n  res.send('ok');\n}\n"
    result = _parser.parse_file(Path("pages/api/users/[id].js"), text)
    assert len(result.routes) == 1
    route = result.routes[0]
    assert route.method == "ANY"
    assert route.path == "/api/users/:id"
    assert route.framework == "nextjs_pages_router"


def test_nestjs_controller_route_joins_class_prefix_and_method_path() -> None:
    text = (
        "@Controller('cats')\n"
        "export class CatsController {\n"
        "  @Get()\n"
        "  findAll(): string { return ''; }\n\n"
        "  @Get(':id')\n"
        "  findOne(): string { return ''; }\n"
        "}\n"
    )
    result = _parser.parse_file(Path("cats.controller.ts"), text)
    routes = {(route.method, route.path, route.handler) for route in result.routes}
    assert ("GET", "/cats", "findAll") in routes
    assert ("GET", "/cats/:id", "findOne") in routes
    assert all(route.framework == "nestjs" for route in result.routes)


def test_nestjs_controller_route_with_no_prefix_and_multiple_http_methods() -> None:
    text = (
        "@Controller()\n"
        "export class RootController {\n"
        "  @Post()\n"
        "  create(): void {}\n\n"
        "  @Delete(':id')\n"
        "  remove(): void {}\n"
        "}\n"
    )
    result = _parser.parse_file(Path("root.controller.ts"), text)
    routes = {(route.method, route.path, route.handler) for route in result.routes}
    assert ("POST", "/", "create") in routes
    assert ("DELETE", "/:id", "remove") in routes


def test_nestjs_extra_decorator_between_controller_and_http_method_is_ignored() -> None:
    text = (
        "@Controller('cats')\n"
        "export class CatsController {\n"
        "  @UseGuards(AuthGuard)\n"
        "  @Get()\n"
        "  findAll(): string { return ''; }\n"
        "}\n"
    )
    result = _parser.parse_file(Path("cats.controller.ts"), text)
    assert len(result.routes) == 1
    assert result.routes[0].method == "GET"
    assert result.routes[0].path == "/cats"


def test_class_without_controller_decorator_produces_no_nestjs_routes() -> None:
    text = "export class PlainService {\n  @Get()\n  doThing() {}\n}\n"
    result = _parser.parse_file(Path("plain.service.ts"), text)
    assert result.routes == []


def test_method_without_http_decorator_inside_controller_is_not_a_route() -> None:
    text = (
        "@Controller('cats')\n"
        "export class CatsController {\n"
        "  private helper(): void {}\n\n"
        "  @Get()\n"
        "  findAll(): string { return ''; }\n"
        "}\n"
    )
    result = _parser.parse_file(Path("cats.controller.ts"), text)
    assert len(result.routes) == 1
    assert result.routes[0].handler == "findAll"
