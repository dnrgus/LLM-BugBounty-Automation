from __future__ import annotations

import ast
import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

from attack_surface.models import AttackSurfaceItem
from scope.policy import method_risk

# P4.5 WP-01 (v5.0 plan 5.1): the endpoint inventory -- one EndpointSpec
# per (route, concrete HTTP method), including state-changing methods,
# with whatever request shape can be inferred statically. A captured or
# explicitly user-supplied request always wins over inference
# ("기존 캡처 요청이나 명시적 사용자 입력이 있으면 추론보다 실제 요청 구조를 우선").

BodyFormat = str  # "none" | "json" | "form" | "multipart"

_PATH_PARAM_PATTERNS = (
    re.compile(r"<(?:[^:<>]+:)?([^<>]+)>"),  # Flask <int:id> / <id>
    re.compile(r"\{([^{}:]+)(?::[^{}]*)?\}"),  # FastAPI/OpenAPI {id}
    re.compile(r":([A-Za-z_][A-Za-z0-9_]*)"),  # Express :id
    re.compile(r"\[(?:\.\.\.)?([A-Za-z_][A-Za-z0-9_]*)\]"),  # Next.js [id] / [...slug]
)


@dataclass(frozen=True)
class EndpointSpec:
    method: str
    path: str
    handler: str | None = None
    file: str | None = None
    line: int | None = None
    framework: str | None = None
    path_params: list[str] = field(default_factory=list)
    query_params: list[str] = field(default_factory=list)
    body_format: BodyFormat = "none"
    body_fields: list[str] = field(default_factory=list)
    schema_source: str = "none"  # "none" | "inferred" | "captured" | "user"
    example_body: dict[str, Any] | None = None
    static_candidate_id: str | None = None

    @property
    def id(self) -> str:
        # Deterministic across re-scans (unlike AttackSurfaceItem's random
        # id) so `validate`/`reproduce` can refer back to it.
        key = f"{self.method}:{self.path}:{self.file}:{self.line}"
        return "EP_" + hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]

    @property
    def risk(self) -> str:
        return method_risk(self.method)

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "method": self.method,
            "path": self.path,
            "handler": self.handler,
            "file": self.file,
            "line": self.line,
            "framework": self.framework,
            "risk": self.risk,
            "path_params": list(self.path_params),
            "query_params": list(self.query_params),
            "body_format": self.body_format,
            "body_fields": list(self.body_fields),
            "schema_source": self.schema_source,
            "example_body": self.example_body,
            "static_candidate_id": self.static_candidate_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EndpointSpec:
        return cls(
            method=str(data["method"]),
            path=str(data["path"]),
            handler=data.get("handler"),
            file=data.get("file"),
            line=data.get("line"),
            framework=data.get("framework"),
            path_params=list(data.get("path_params", [])),
            query_params=list(data.get("query_params", [])),
            body_format=str(data.get("body_format", "none")),
            body_fields=list(data.get("body_fields", [])),
            schema_source=str(data.get("schema_source", "none")),
            example_body=data.get("example_body"),
            static_candidate_id=data.get("static_candidate_id"),
        )


@dataclass(frozen=True)
class CapturedRequest:
    """A real request observed by the tester (proxy export / HAR / hand-
    written JSON). Only the *shape* is kept -- header names, never header
    values, since those are where session credentials live."""

    method: str
    path: str
    query_params: list[str] = field(default_factory=list)
    content_type: str | None = None
    body: dict[str, Any] | None = None
    header_names: list[str] = field(default_factory=list)


def expand_methods(label: str) -> list[str]:
    """Route method labels -> concrete methods. Flask's bare
    @app.route(...) ("ROUTE") really is GET-only by default; "ANY"
    (Django path(), Next.js default export) has no declared method, so
    only the safe baseline GET is inventoried for it."""
    tokens = [token.strip().upper() for token in label.split("|") if token.strip()]
    methods = [token for token in tokens if token not in {"ROUTE", "ANY"}]
    return sorted(set(methods)) or ["GET"]


def extract_path_params(path: str) -> list[str]:
    names: list[str] = []
    for pattern in _PATH_PARAM_PATTERNS:
        for match in pattern.finditer(path):
            name = match.group(1).strip()
            if name and name not in names:
                names.append(name)
    return names


def path_template_regex(path: str) -> re.Pattern[str]:
    """Compiles a route template (any of the supported param syntaxes)
    into a regex matching concrete paths, for captured-request matching."""
    placeholder = "\x00"
    templated = path
    for pattern in _PATH_PARAM_PATTERNS:
        templated = pattern.sub(placeholder, templated)
    escaped = re.escape(templated).replace(re.escape(placeholder), "[^/]+").replace(placeholder, "[^/]+")
    return re.compile("^" + escaped.rstrip("/") + "/?$")


# --- static body inference --------------------------------------------------

_JS_BODY_FIELD = re.compile(r"\b(?:req|request)\.body\.([A-Za-z_$][\w$]*)")
_JS_BODY_SUBSCRIPT = re.compile(r"\b(?:req|request)\.body\[\s*['\"]([^'\"]+)['\"]\s*\]")
_JS_BODY_DESTRUCTURE = re.compile(r"\{([^{}]+)\}\s*=\s*(?:await\s+)?(?:req|request)\.(?:body|json\(\))")
_JS_BODY_ANY = re.compile(r"\b(?:req|request)\.body\b|\brequest\.json\(\)|@Body\(")
_JS_FORM = re.compile(r"\brequest\.formData\(\)|urlencoded")
_JS_MULTIPART = re.compile(r"\breq\.files?\b|\bupload\.(?:single|array|fields)\(|@UploadedFiles?\(")
_JS_QUERY_FIELD = re.compile(r"\b(?:req|request)\.query\.([A-Za-z_$][\w$]*)")
_JS_NEST_QUERY = re.compile(r"@Query\(\s*['\"]([^'\"]+)['\"]")


def _infer_js_segment(segment: str) -> tuple[BodyFormat, list[str], list[str]]:
    fields: list[str] = []
    for pattern in (_JS_BODY_FIELD, _JS_BODY_SUBSCRIPT):
        for match in pattern.finditer(segment):
            if match.group(1) not in fields:
                fields.append(match.group(1))
    for match in _JS_BODY_DESTRUCTURE.finditer(segment):
        for part in match.group(1).split(","):
            name = part.split(":")[0].split("=")[0].strip().lstrip(".")
            if name and re.fullmatch(r"[A-Za-z_$][\w$]*", name) and name not in fields:
                fields.append(name)
    query: list[str] = []
    for pattern in (_JS_QUERY_FIELD, _JS_NEST_QUERY):
        for match in pattern.finditer(segment):
            if match.group(1) not in query:
                query.append(match.group(1))

    if _JS_MULTIPART.search(segment):
        body_format = "multipart"
    elif _JS_FORM.search(segment):
        body_format = "form"
    elif fields or _JS_BODY_ANY.search(segment):
        body_format = "json"
    else:
        body_format = "none"
    return body_format, fields, query


def _python_handler(tree: ast.Module, handler: str) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == handler:
            return node
    return None


def _str_arg(call: ast.Call) -> str | None:
    if call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
        return call.args[0].value
    return None


def _request_attr_chain(node: ast.expr) -> str | None:
    """`request.json` -> "json", `request.get_json()` -> "json",
    `request.form` -> "form", etc. None if not rooted at `request`."""
    if isinstance(node, ast.Call):
        node = node.func
        if isinstance(node, ast.Attribute) and node.attr == "get_json":
            return "json" if isinstance(node.value, ast.Name) and node.value.id == "request" else None
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "request":
        return node.attr
    return None


def _infer_python_handler(
    tree: ast.Module, func: ast.FunctionDef | ast.AsyncFunctionDef, path_params: list[str]
) -> tuple[BodyFormat, list[str], list[str]]:
    body_kinds: set[str] = set()
    fields: list[str] = []
    query: list[str] = []

    def add(bucket: list[str], name: str | None) -> None:
        if name and name not in bucket:
            bucket.append(name)

    # `payload = request.get_json()` / `data = request.form` -- one level
    # of aliasing, so `payload["title"]` still counts as a body field.
    aliases: dict[str, str] = {}
    for node in ast.walk(func):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            kind = _request_attr_chain(node.value) if isinstance(node.value, (ast.Attribute, ast.Call)) else None
            if kind in {"json", "form", "args", "files"}:
                aliases[node.targets[0].id] = kind

    def kind_of(expr: ast.expr) -> str | None:
        if isinstance(expr, ast.Name):
            return aliases.get(expr.id)
        return _request_attr_chain(expr)

    for node in ast.walk(func):
        # request.json.get("x") / request.form.get("x") / request.args.get("x")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get":
            kind = kind_of(node.func.value)
            if kind in {"json", "form", "values"}:
                body_kinds.add("json" if kind == "json" else "form")
                add(fields, _str_arg(node))
            elif kind == "args":
                add(query, _str_arg(node))
        # request.json["x"] / request.form["x"] / request.args["x"]
        if isinstance(node, ast.Subscript):
            kind = kind_of(node.value)
            key = node.slice.value if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str) else None
            if kind in {"json", "form"}:
                body_kinds.add(kind)
                add(fields, key)
            elif kind == "files":
                body_kinds.add("multipart")
                add(fields, key)
            elif kind == "args":
                add(query, key)
        kind = _request_attr_chain(node) if isinstance(node, (ast.Attribute, ast.Call)) else None
        if kind in {"json", "data"}:
            body_kinds.add("json")
        elif kind == "form":
            body_kinds.add("form")
        elif kind == "files":
            body_kinds.add("multipart")

    # FastAPI: a parameter annotated with a same-file pydantic model is a
    # JSON body; a plain scalar parameter that isn't a path param (and
    # isn't a Depends(...)) is a query param.
    models = _pydantic_models(tree)
    args = func.args.args
    defaults = [None] * (len(args) - len(func.args.defaults)) + list(func.args.defaults)
    for arg, default in zip(args, defaults):
        annotation = arg.annotation
        if isinstance(annotation, ast.Name) and annotation.id in models:
            body_kinds.add("json")
            for model_field in models[annotation.id]:
                add(fields, model_field)
            continue
        if isinstance(default, ast.Call) and isinstance(default.func, ast.Name):
            if default.func.id in {"Form", "File", "UploadFile"}:
                body_kinds.add("multipart" if default.func.id != "Form" else "form")
                add(fields, arg.arg)
                continue
            if default.func.id == "Body":
                body_kinds.add("json")
                add(fields, arg.arg)
                continue
            if default.func.id == "Query":
                add(query, arg.arg)
                continue
            if default.func.id == "Depends":
                continue
        if isinstance(annotation, ast.Name) and annotation.id in {"int", "str", "float", "bool"} and arg.arg not in path_params:
            add(query, arg.arg)

    if "multipart" in body_kinds:
        body_format = "multipart"
    elif "json" in body_kinds:
        body_format = "json"
    elif "form" in body_kinds:
        body_format = "form"
    else:
        body_format = "none"
    return body_format, fields, query


def _pydantic_models(tree: ast.Module) -> dict[str, list[str]]:
    models: dict[str, list[str]] = {}
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        bases = {base.id if isinstance(base, ast.Name) else getattr(base, "attr", None) for base in node.bases}
        if "BaseModel" not in bases:
            continue
        models[node.name] = [
            stmt.target.id for stmt in node.body if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name)
        ]
    return models


class _SourceCache:
    def __init__(self) -> None:
        self._text: dict[str, str | None] = {}
        self._tree: dict[str, ast.Module | None] = {}

    def text(self, file: str) -> str | None:
        if file not in self._text:
            try:
                self._text[file] = Path(file).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                self._text[file] = None
        return self._text[file]

    def python_tree(self, file: str) -> ast.Module | None:
        if file not in self._tree:
            text = self.text(file)
            try:
                self._tree[file] = ast.parse(text) if text is not None else None
            except (SyntaxError, ValueError):
                self._tree[file] = None
        return self._tree[file]


def _js_segment(text: str, line: int, next_route_line: int | None) -> str:
    """Handler text for a JS/TS route: from its route line to just before
    the next route in the same file (or EOF). A deterministic segment
    heuristic -- no cross-file resolution of a handler imported from
    elsewhere (documented WP-05 territory)."""
    lines = text.splitlines()
    end = (next_route_line - 1) if next_route_line else len(lines)
    return "\n".join(lines[line - 1 : end])


def build_endpoint_inventory(
    items: list[AttackSurfaceItem], captured: list[CapturedRequest] | None = None
) -> list[EndpointSpec]:
    """Endpoint AttackSurfaceItems (source/routes.py) -> EndpointSpecs,
    one per concrete method. GET/HEAD/OPTIONS and POST/PUT/PATCH/DELETE
    are all inventoried; whether any of them may actually be *sent* is
    PolicyEngine.decide_method's call, not this module's."""
    cache = _SourceCache()
    endpoint_items = [item for item in items if item.asset_type == "endpoint"]

    route_lines_by_file: dict[str, list[int]] = {}
    for item in endpoint_items:
        file = item.metadata.get("file")
        if file and item.metadata.get("line"):
            route_lines_by_file.setdefault(str(file), []).append(int(item.metadata["line"]))
    for lines in route_lines_by_file.values():
        lines.sort()

    specs: list[EndpointSpec] = []
    seen: set[str] = set()
    for item in endpoint_items:
        file = str(item.metadata["file"]) if item.metadata.get("file") else None
        line = int(item.metadata["line"]) if item.metadata.get("line") else None
        handler = item.metadata.get("handler")
        path_params = extract_path_params(item.location)
        body_format, fields, query = _infer_shape(cache, file, line, handler, path_params, route_lines_by_file)
        for method in expand_methods(str(item.metadata.get("method", "GET"))):
            method_body_format = body_format if method not in {"GET", "HEAD", "OPTIONS"} else "none"
            spec = EndpointSpec(
                method=method,
                path=item.location,
                handler=str(handler) if handler else None,
                file=file,
                line=line,
                framework=item.metadata.get("framework"),
                path_params=path_params,
                query_params=query,
                body_format=method_body_format,
                body_fields=fields if method_body_format != "none" else [],
                schema_source="inferred" if (method_body_format != "none" or query) else "none",
                static_candidate_id=item.id,
            )
            if spec.id in seen:
                continue
            seen.add(spec.id)
            specs.append(spec)

    if captured:
        specs = [apply_captured_request(spec, captured) for spec in specs]
    return specs


def _infer_shape(
    cache: _SourceCache,
    file: str | None,
    line: int | None,
    handler: object,
    path_params: list[str],
    route_lines_by_file: dict[str, list[int]],
) -> tuple[BodyFormat, list[str], list[str]]:
    if not file:
        return "none", [], []
    if file.endswith(".py"):
        tree = cache.python_tree(file)
        func = _python_handler(tree, str(handler)) if tree is not None and handler else None
        if func is None:
            return "none", [], []
        return _infer_python_handler(tree, func, path_params)
    text = cache.text(file)
    if text is None or line is None:
        return "none", [], []
    later = [candidate for candidate in route_lines_by_file.get(file, []) if candidate > line]
    return _infer_js_segment(_js_segment(text, line, later[0] if later else None))


# --- captured / user-supplied requests ------------------------------------------


def _body_format_for_content_type(content_type: str | None) -> BodyFormat:
    lowered = (content_type or "").lower()
    if "multipart" in lowered:
        return "multipart"
    if "x-www-form-urlencoded" in lowered:
        return "form"
    if "json" in lowered:
        return "json"
    return "none"


def apply_captured_request(spec: EndpointSpec, captured: list[CapturedRequest]) -> EndpointSpec:
    regex = path_template_regex(spec.path)
    for request in captured:
        if request.method.upper() != spec.method or not regex.match(request.path):
            continue
        body_format = _body_format_for_content_type(request.content_type)
        if body_format == "none" and request.body:
            body_format = "json"
        return replace(
            spec,
            body_format=body_format,
            body_fields=sorted(request.body.keys()) if request.body else [],
            query_params=sorted(set(spec.query_params) | set(request.query_params)),
            schema_source="captured",
            example_body=request.body,
        )
    return spec


def load_captured_requests(path: Path | str) -> list[CapturedRequest]:
    """Accepts either a HAR file (log.entries[].request) or a plain JSON
    list of {method, url|path, content_type?, body?, headers?}."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "log" in data:
        return [_from_har_request(entry.get("request", {})) for entry in data["log"].get("entries", [])]
    if isinstance(data, dict):
        data = data.get("requests", [])
    return [_from_plain(entry) for entry in data]


def _from_plain(entry: dict[str, Any]) -> CapturedRequest:
    target = str(entry.get("url") or entry.get("path") or "/")
    parsed = urlparse(target)
    body = entry.get("body")
    if isinstance(body, str):
        body = _parse_body_text(body, entry.get("content_type"))
    headers = entry.get("headers") or {}
    return CapturedRequest(
        method=str(entry.get("method", "GET")).upper(),
        path=parsed.path or "/",
        query_params=sorted({key for key, _ in parse_qsl(parsed.query)}),
        content_type=entry.get("content_type") or _header(headers, "content-type"),
        body=body if isinstance(body, dict) else None,
        header_names=sorted(str(name).lower() for name in headers),
    )


def _from_har_request(request: dict[str, Any]) -> CapturedRequest:
    parsed = urlparse(str(request.get("url", "/")))
    post_data = request.get("postData") or {}
    content_type = post_data.get("mimeType")
    body: dict[str, Any] | None = None
    if post_data.get("params"):
        body = {param["name"]: param.get("value", "") for param in post_data["params"] if "name" in param}
    elif post_data.get("text"):
        body = _parse_body_text(post_data["text"], content_type)
    return CapturedRequest(
        method=str(request.get("method", "GET")).upper(),
        path=parsed.path or "/",
        query_params=sorted({key for key, _ in parse_qsl(parsed.query)}),
        content_type=content_type,
        body=body,
        header_names=sorted(str(header.get("name", "")).lower() for header in request.get("headers", [])),
    )


def _parse_body_text(text: str, content_type: str | None) -> dict[str, Any] | None:
    if _body_format_for_content_type(content_type) == "form":
        return dict(parse_qsl(text))
    try:
        parsed = json.loads(text)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _header(headers: dict[str, Any], name: str) -> str | None:
    for key, value in headers.items():
        if str(key).lower() == name:
            return str(value)
    return None
