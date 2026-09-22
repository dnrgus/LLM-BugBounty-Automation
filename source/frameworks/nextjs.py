from __future__ import annotations

from pathlib import Path

# P3.2-2 (roadmap v3.2.0 Source Intelligence): Next.js API routes are
# defined by file *path* convention, not by a call/decorator the way
# Flask/FastAPI/Express are -- Pages Router (`pages/api/**`, one default-
# exported handler, method branching happens at runtime on req.method so
# it's reported as "ANY") and App Router (`app/**/route.{js,ts,jsx,tsx}`,
# one exported function per HTTP method name).
_APP_ROUTE_FILENAMES = {"route.js", "route.jsx", "route.ts", "route.tsx"}


def is_pages_api_route(path: Path) -> bool:
    parts = path.parts
    if "pages" not in parts:
        return False
    return "api" in parts[parts.index("pages") :]


def is_app_router_route_file(path: Path) -> bool:
    return path.name in _APP_ROUTE_FILENAMES and "app" in path.parts


def pages_api_route_path(path: Path) -> str:
    parts = list(path.parts)
    suffix = parts[parts.index("pages") + 1 :]
    suffix[-1] = Path(suffix[-1]).stem
    if suffix and suffix[-1] == "index":
        suffix = suffix[:-1]
    return "/" + "/".join(_convert_segment(segment) for segment in suffix)


def app_router_route_path(path: Path) -> str:
    parts = list(path.parts)
    app_index = parts.index("app")
    suffix = parts[app_index + 1 : -1]  # drop "app" and the trailing route.ext filename
    # A route group directory like "(marketing)" organizes files without
    # appearing in the URL, so it's dropped rather than converted.
    suffix = [segment for segment in suffix if not (segment.startswith("(") and segment.endswith(")"))]
    segments = [_convert_segment(segment) for segment in suffix]
    return "/" + "/".join(segments) if segments else "/"


def _convert_segment(segment: str) -> str:
    if segment.startswith("[...") and segment.endswith("]"):
        return f"*{segment[4:-1]}"
    if segment.startswith("[") and segment.endswith("]"):
        return f":{segment[1:-1]}"
    return segment
