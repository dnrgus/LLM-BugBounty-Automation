from __future__ import annotations

from urllib.parse import urlparse

from attack_surface.models import AttackSurfaceItem

_CONFIDENCE_BOOST_STATIC_DYNAMIC = 0.15
_CONFIDENCE_BOOST_LLM_SDK_MATCH = 0.10


def _endpoint_key(item: AttackSurfaceItem) -> tuple[str, str] | None:
    if item.asset_type != "endpoint":
        return None
    method = str(item.metadata.get("method", "GET")).upper()
    path = urlparse(item.location).path or item.location
    return (method, path)


def _parameter_key(item: AttackSurfaceItem) -> tuple[str, str] | None:
    if item.asset_type != "parameter":
        return None
    name = item.metadata.get("name")
    if name is None:
        return None
    position = item.metadata.get("position", "")
    return (str(name), str(position))


def merge_items(items: list[AttackSurfaceItem]) -> list[AttackSurfaceItem]:
    """Applies the design doc's merge rules (section 5.2):

    - same (method, path) endpoint -> merged into one candidate
    - same (parameter name, position) -> merged into one input surface
    - a source-only item merging with a live-only item for the same key
      raises confidence (static+dynamic agreement) and the result's
      source_type becomes "merged"
    - an llm_detected item merging with another source's llm_detected item
      raises confidence further (LLM Pack priority signal)
    - conflicting metadata is never overwritten: every contributing item's
      original fields are kept in `provenance`, and only non-conflicting
      keys are promoted to the merged item's own metadata
    """
    buckets: dict[tuple[str, tuple[str, str]], list[AttackSurfaceItem]] = {}
    unmergeable: list[AttackSurfaceItem] = []

    for item in items:
        key = _endpoint_key(item) or _parameter_key(item)
        if key is None:
            unmergeable.append(item)
            continue
        buckets.setdefault((item.asset_type, key), []).append(item)

    merged: list[AttackSurfaceItem] = list(unmergeable)
    for group in buckets.values():
        merged.append(group[0] if len(group) == 1 else _merge_group(group))
    return merged


def _merge_group(group: list[AttackSurfaceItem]) -> AttackSurfaceItem:
    source_types = {item.source_type for item in group}
    has_static = "source" in source_types
    has_live = "live" in source_types

    confidence = max(item.confidence for item in group)
    if has_static and has_live:
        confidence = min(1.0, confidence + _CONFIDENCE_BOOST_STATIC_DYNAMIC)

    llm_detected = any(bool(item.metadata.get("llm_detected")) for item in group)
    if llm_detected and has_static and has_live:
        confidence = min(1.0, confidence + _CONFIDENCE_BOOST_LLM_SDK_MATCH)

    merged_metadata: dict[str, object] = {}
    conflicting_keys: set[str] = set()
    for item in group:
        for key, value in item.metadata.items():
            if key in merged_metadata and merged_metadata[key] != value:
                conflicting_keys.add(key)
            else:
                merged_metadata[key] = value
    for key in conflicting_keys:
        merged_metadata.pop(key, None)
    if llm_detected:
        merged_metadata["llm_detected"] = True

    provenance = [
        {"source_type": item.source_type, "id": item.id, "metadata": item.metadata} for item in group
    ]
    evidence_refs = sorted({ref for item in group for ref in item.evidence_refs})
    correlation_keys = sorted({key for item in group for key in item.correlation_keys})
    representative = group[0]

    return AttackSurfaceItem(
        source_type="merged" if (has_static and has_live) else representative.source_type,
        asset_type=representative.asset_type,
        location=representative.location,
        metadata=merged_metadata,
        confidence=round(confidence, 3),
        evidence_refs=evidence_refs,
        correlation_keys=correlation_keys,
        provenance=provenance,
    )
