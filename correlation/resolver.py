from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from attack_surface.models import AttackSurfaceItem

_PARAM_TOKEN = "{param}"
# Matches a templated parameter segment in any of this project's route
# syntaxes: Flask `<id>`/`<int:id>`, FastAPI `{id}`, or this project's own
# `:id`/`*slug` convention (source/frameworks/nextjs.py, live discovery's
# JS-extracted API paths).
_TEMPLATE_PARAM_RE = re.compile(r"^(?:<[^>]+>|\{[^}]+\}|:[A-Za-z_][A-Za-z0-9_]*|\*[A-Za-z_][A-Za-z0-9_]*)$")
# A *concrete* live segment that plausibly stands in for a template
# parameter -- numeric, UUID, Mongo ObjectId, or a long hex/alnum token.
_ID_LIKE_SEGMENT_RE = re.compile(
    r"^(?:\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{16,})$"
)
_VERSION_PREFIX_RE = re.compile(r"^/v\d+(?:\.\d+)?(?=/|$)", re.IGNORECASE)

_REVIEW_THRESHOLD = 0.6


def canonicalize_path(path: str) -> str:
    """Normalizes a path for source<->live comparison: leading slash,
    no trailing slash (except root), and every templated *or*
    ID-shaped concrete segment collapsed to one canonical {param}
    token -- so a source route declared as `/api/users/<int:id>` (or
    `/api/users/{id}`, or `/api/users/:id`) compares equal to a live-
    observed concrete URL `/api/users/123`.
    """
    normalized = path if path.startswith("/") else f"/{path}"
    normalized = normalized.rstrip("/") or "/"
    segments = normalized.split("/")
    return "/".join(_canonicalize_segment(segment) for segment in segments)


def _canonicalize_segment(segment: str) -> str:
    if _TEMPLATE_PARAM_RE.match(segment):
        return _PARAM_TOKEN
    if segment and _ID_LIKE_SEGMENT_RE.match(segment):
        return _PARAM_TOKEN
    return segment


def strip_version_prefix(path: str) -> str:
    """Drops a leading `/v1`, `/v2.1`, etc. segment, if present."""
    return _VERSION_PREFIX_RE.sub("", path) or "/"


@dataclass(frozen=True)
class EntityMatch:
    """One candidate (source route, live endpoint) pairing. `basis`
    records exactly why they were considered a match -- required reading
    before trusting a match enough to attempt live validation against it
    (P3.3-3), per the roadmap's own DoD: confidence and matching
    evidence are recorded, and a low-confidence match is marked
    review_required rather than treated as good enough to act on
    automatically.
    """

    source_item: AttackSurfaceItem
    live_item: AttackSurfaceItem
    confidence: float
    basis: list[str] = field(default_factory=list)

    @property
    def review_required(self) -> bool:
        return self.confidence < _REVIEW_THRESHOLD

    def to_dict(self) -> dict[str, object]:
        return {
            "source_item_id": self.source_item.id,
            "live_item_id": self.live_item.id,
            "source_location": self.source_item.location,
            "live_location": self.live_item.location,
            "confidence": round(self.confidence, 3),
            "basis": self.basis,
            "review_required": self.review_required,
        }


def resolve_entities(source_items: list[AttackSurfaceItem], live_items: list[AttackSurfaceItem]) -> list[EntityMatch]:
    """P3.3-1 (roadmap v3.3.0 Static -> Dynamic Validation): matches
    SOURCE-derived routes to LIVE-observed endpoints more robustly than
    attack_surface/merge.py's exact (method, path) match -- path-
    parameter canonicalization, version-prefix and reverse-proxy-prefix
    tolerance -- without silently promoting a shaky guess.

    Deliberately endpoint-only for this phase (not "parameter", which
    stays on the existing exact-match merge_items() path) and additive:
    this does not replace attack_surface/merge.py, which callers using
    `correlate` unchanged still rely on for its confidence-boost
    behavior. This is the richer entity-resolution layer P3.3-3's
    Dynamic Validator will consume when deciding whether a static
    candidate is even reachable to validate live.

    Live discovery only ever issues GET requests (its own safety
    invariant -- see live/discovery.py), so a live item's declared
    "method" reflects how it was *probed*, not necessarily every method
    the endpoint actually accepts. Matching therefore keys on path, not
    method: a source route declaring a non-GET method still matches a
    GET-discovered path, just at reduced confidence (basis explains
    why).
    """
    matches: list[EntityMatch] = []
    for source_item in source_items:
        source_sig = _endpoint_signature(source_item)
        if source_sig is None:
            continue
        for live_item in live_items:
            live_sig = _endpoint_signature(live_item)
            if live_sig is None:
                continue
            match = _match_one(source_item, source_sig, live_item, live_sig)
            if match is not None:
                matches.append(match)
    return matches


def _endpoint_signature(item: AttackSurfaceItem) -> tuple[str, str] | None:
    if item.asset_type != "endpoint":
        return None
    method = str(item.metadata.get("method", "GET")).upper()
    path = urlparse(item.location).path or item.location
    return method, path


def _accepts_get(method: str) -> bool:
    return method in {"GET", "ROUTE", "ANY"} or "GET" in method.split("|")


def _match_one(
    source_item: AttackSurfaceItem,
    source_sig: tuple[str, str],
    live_item: AttackSurfaceItem,
    live_sig: tuple[str, str],
) -> EntityMatch | None:
    source_method, source_path = source_sig
    _, live_path = live_sig

    source_canon = canonicalize_path(source_path)
    live_canon = canonicalize_path(live_path)
    method_caveat = not _accepts_get(source_method)

    if source_canon == live_canon:
        basis = ["exact_path"] if source_path == live_path else ["canonicalized_path_match"]
        confidence = 0.9 if source_path == live_path else 0.8
        if method_caveat:
            basis.append("source_declares_non_get_method_live_only_probed_via_get")
            confidence -= 0.2
        return EntityMatch(source_item, live_item, max(confidence, 0.3), basis)

    source_no_version = canonicalize_path(strip_version_prefix(source_path))
    live_no_version = canonicalize_path(strip_version_prefix(live_path))
    if source_no_version == live_no_version:
        basis = ["version_prefix_tolerant_match"]
        if method_caveat:
            basis.append("source_declares_non_get_method_live_only_probed_via_get")
        return EntityMatch(source_item, live_item, 0.55 if method_caveat else 0.65, basis)

    if source_canon != "/" and live_canon.endswith(source_canon):
        basis = ["proxy_prefix_suffix_match"]
        if method_caveat:
            basis.append("source_declares_non_get_method_live_only_probed_via_get")
        return EntityMatch(source_item, live_item, 0.4 if method_caveat else 0.5, basis)

    return None
