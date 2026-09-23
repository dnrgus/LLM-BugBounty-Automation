"""P4.2-D NestJS @UseGuards() detection (roadmap v4.2.0 Source
Intelligence Expansion) -- the JS/TS equivalent of
tests/test_auth_python.py."""

from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")

from source.auth.javascript import find_auth_guards  # noqa: E402


def _controller_text(method_decorators: str) -> str:
    return (
        "@Controller('cats')\n"
        "export class CatsController {\n"
        f"{method_decorators}"
        "  findAll(): string { return ''; }\n"
        "}\n"
    )


def test_detects_use_guards_decorator() -> None:
    text = _controller_text("  @UseGuards(AuthGuard)\n  @Get()\n")
    hints = find_auth_guards(Path("cats.controller.ts"), text, {"findAll"})
    assert len(hints) == 1
    assert hints[0].detected is True
    assert hints[0].guard_names == ["AuthGuard"]
    assert hints[0].confidence == 0.7


def test_no_use_guards_decorator_reports_not_detected() -> None:
    text = _controller_text("  @Get()\n")
    hints = find_auth_guards(Path("cats.controller.ts"), text, {"findAll"})
    assert len(hints) == 1
    assert hints[0].detected is False
    assert hints[0].guard_names == []
    assert "NOT proof" in hints[0].note


def test_multiple_guard_arguments_are_all_recorded() -> None:
    text = _controller_text("  @UseGuards(AuthGuard, RolesGuard)\n  @Get()\n")
    hints = find_auth_guards(Path("cats.controller.ts"), text, {"findAll"})
    assert hints[0].guard_names == ["AuthGuard", "RolesGuard"]


def test_method_not_in_route_handlers_is_ignored() -> None:
    text = _controller_text("  @Get()\n")
    hints = find_auth_guards(Path("cats.controller.ts"), text, {"someOtherHandler"})
    assert hints == []


def test_empty_route_handlers_returns_no_hints_without_parsing() -> None:
    hints = find_auth_guards(Path("cats.controller.ts"), "not even valid { { {", set())
    assert hints == []


def test_syntax_error_returns_no_hints_instead_of_raising() -> None:
    hints = find_auth_guards(Path("broken.ts"), "class ( { { { not valid", {"findAll"})
    assert hints == []
