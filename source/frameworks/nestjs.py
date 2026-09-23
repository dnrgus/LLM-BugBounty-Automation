from __future__ import annotations

# P4.2-C (roadmap v4.2.0 Source Intelligence Expansion): NestJS route
# decorators -- @Controller(prefix) on a class, @Get()/@Post()/etc. on
# its methods. Mirrors source/frameworks/express.py's narrow-allowlist
# philosophy: only these recognized decorator names count, so some
# unrelated `@Get()`-shaped decorator from another library doesn't
# false-positive as a NestJS route.
_HTTP_METHOD_DECORATORS = {
    "Get": "GET",
    "Post": "POST",
    "Put": "PUT",
    "Delete": "DELETE",
    "Patch": "PATCH",
    "Head": "HEAD",
    "Options": "OPTIONS",
    "All": "ANY",
}
CONTROLLER_DECORATOR = "Controller"


def http_method_for_decorator(decorator_name: str) -> str | None:
    return _HTTP_METHOD_DECORATORS.get(decorator_name)


def is_controller_decorator(decorator_name: str) -> bool:
    return decorator_name == CONTROLLER_DECORATOR


def join_route_path(prefix: str, method_path: str) -> str:
    """NestJS joins a @Controller('prefix') class-level prefix with each
    @Get('sub')-declared method path into one route path, both parts
    optional/defaultable to "" -- e.g. Controller('cats') + Get(':id')
    -> '/cats/:id'; Controller() + Get() -> '/'."""
    segments = [segment.strip("/") for segment in (prefix, method_path) if segment]
    return "/" + "/".join(segments) if segments else "/"
