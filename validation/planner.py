from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import yaml

from attack_surface.models import AttackSurfaceItem
from correlation.resolver import EntityMatch

Classification = Literal["executable", "review_only", "unsupported"]

# A dataflow sink whose category is potentially destructive (remote code
# execution, arbitrary file access, unsafe deserialization, template
# injection) never gets auto-classified as executable, no matter how good
# its live match is -- roadmap's own rule: "destructive categories는
# simulate/approval".
_DESTRUCTIVE_SINK_TYPES = {"os_command", "deserialization", "code_execution", "file_access", "template_injection"}

_DEFAULT_TEMPLATES_PATH = Path(__file__).resolve().parent / "templates" / "categories.yaml"


@dataclass(frozen=True)
class ValidationPlan:
    """P3.3-2 (roadmap v3.3.0 Static -> Dynamic Validation): what, if
    anything, should happen next for one static AttackSurfaceItem
    candidate. Never claims more certainty than the evidence supports --
    `classification` is one of "executable" (a real, already-built
    executor can test this live and, per DoD, this alone is not a
    confirmed finding until that executor actually runs and a Judge/
    Reproducer confirms it), "review_only" (a validation path exists in
    principle but needs a human decision/context first), or
    "unsupported" (no dynamic validation concept applies to this finding
    type at all, e.g. a source-detected secret).
    """

    candidate_id: str
    asset_type: str
    classification: Classification
    reason: str
    required_context: list[str] = field(default_factory=list)
    control_test: str | None = None
    success_criteria: str | None = None
    requires_approval: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id,
            "asset_type": self.asset_type,
            "classification": self.classification,
            "reason": self.reason,
            "required_context": self.required_context,
            "control_test": self.control_test,
            "success_criteria": self.success_criteria,
            "requires_approval": self.requires_approval,
        }


def load_templates(path: Path | str = _DEFAULT_TEMPLATES_PATH) -> dict[str, dict[str, object]]:
    with Path(path).open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    return data.get("categories", {})


def generate_validation_plans(
    items: list[AttackSurfaceItem],
    matches: list[EntityMatch] | None = None,
    auth_context_available: bool = False,
    templates: dict[str, dict[str, object]] | None = None,
) -> list[ValidationPlan]:
    """Batch entrypoint: plans every item, cross-referencing entity
    matches (P3.3-1) and, for endpoints, this file's own auth-guard
    candidates (P3.2-4) by handler name.
    """
    templates = templates if templates is not None else load_templates()
    matched_by_source_id = {match.source_item.id: match for match in (matches or [])}

    auth_guard_by_handler: dict[str, bool] = {
        str(item.metadata["handler"]): bool(item.metadata.get("detected"))
        for item in items
        if item.asset_type == "auth" and item.metadata.get("handler")
    }
    endpoint_items_by_file: dict[str, list[AttackSurfaceItem]] = {}
    for item in items:
        if item.asset_type == "endpoint" and item.metadata.get("file"):
            endpoint_items_by_file.setdefault(str(item.metadata["file"]), []).append(item)

    return [
        _plan_one(
            item, templates, matched_by_source_id, auth_context_available, auth_guard_by_handler, endpoint_items_by_file
        )
        for item in items
    ]


def _plan_one(
    item: AttackSurfaceItem,
    templates: dict[str, dict[str, object]],
    matched_by_source_id: dict[str, EntityMatch],
    auth_context_available: bool,
    auth_guard_by_handler: dict[str, bool],
    endpoint_items_by_file: dict[str, list[AttackSurfaceItem]],
) -> ValidationPlan:
    if item.asset_type == "endpoint":
        return _plan_endpoint(item, templates, matched_by_source_id.get(item.id), auth_context_available, auth_guard_by_handler)
    if item.asset_type in {"llm", "rag", "agent"}:
        return _plan_ai_capability(item, templates, matched_by_source_id, endpoint_items_by_file)
    if item.asset_type == "dataflow":
        return _plan_dataflow(item, templates)
    if item.asset_type == "auth":
        return _plan_auth(item, templates)
    if item.asset_type == "secret":
        return _unsupported(item, "secret exposure findings require manual verification/rotation, not dynamic validation")
    # "function" (plain regex sink match) and "parameter" (plain input match):
    # presence-only signals with no traced source->sink path -- see this
    # file's own "dataflow" items for the verified equivalent.
    return _unsupported(
        item, "presence-only static signal with no traced source->sink path; see 'dataflow' items for a verified candidate"
    )


def _plan_endpoint(
    item: AttackSurfaceItem,
    templates: dict[str, dict[str, object]],
    match: EntityMatch | None,
    auth_context_available: bool,
    auth_guard_by_handler: dict[str, bool],
) -> ValidationPlan:
    template = templates.get("endpoint", {})
    if match is None:
        return _unsupported(item, "no corresponding live endpoint found to test against yet -- run discover/scan against this target first")
    if match.review_required:
        return ValidationPlan(
            item.id, item.asset_type, "review_only",
            f"entity match confidence too low to automate ({match.confidence}); basis={match.basis}",
            required_context=["manual_confirmation_of_endpoint_mapping"],
        )
    handler = item.metadata.get("handler")
    if handler and auth_guard_by_handler.get(str(handler)) and not auth_context_available:
        return ValidationPlan(
            item.id, item.asset_type, "review_only",
            "route has a detected auth guard and no authenticated context was supplied",
            required_context=["authenticated_session"],
            control_test=template.get("control_test"), success_criteria=template.get("success_criteria"),
        )
    return ValidationPlan(
        item.id, item.asset_type, "executable",
        f"live-corroborated endpoint (basis={match.basis}) with sufficient match confidence ({match.confidence})",
        control_test=template.get("control_test"), success_criteria=template.get("success_criteria"),
    )


def _plan_ai_capability(
    item: AttackSurfaceItem,
    templates: dict[str, dict[str, object]],
    matched_by_source_id: dict[str, EntityMatch],
    endpoint_items_by_file: dict[str, list[AttackSurfaceItem]],
) -> ValidationPlan:
    template = templates.get(item.asset_type, {})
    same_file_endpoints = endpoint_items_by_file.get(str(item.metadata.get("file", "")), [])
    good_match = next(
        (
            matched_by_source_id[endpoint.id]
            for endpoint in same_file_endpoints
            if endpoint.id in matched_by_source_id and not matched_by_source_id[endpoint.id].review_required
        ),
        None,
    )
    if good_match is None:
        return ValidationPlan(
            item.id, item.asset_type, "review_only",
            "capability signal found in source but no live-corroborated endpoint in the same file yet -- "
            "run discover/scan against this target, then re-plan",
            required_context=["live_endpoint_correlation"],
        )
    return ValidationPlan(
        item.id, item.asset_type, "executable",
        f"a live-corroborated endpoint in the same file lets the existing {template.get('executor')} pipeline test this",
        control_test=template.get("control_test"), success_criteria=template.get("success_criteria"),
    )


def _plan_dataflow(item: AttackSurfaceItem, templates: dict[str, dict[str, object]]) -> ValidationPlan:
    sink_type = str(item.metadata.get("sink_type", ""))
    if sink_type in _DESTRUCTIVE_SINK_TYPES:
        template = templates.get("dataflow_destructive", {})
        return ValidationPlan(
            item.id, item.asset_type, "review_only",
            f"sink category '{sink_type}' is potentially destructive -- requires explicit written authorization "
            "before any live probe, never automated",
            required_context=list(template.get("required_context", [])),
            requires_approval=True,
        )
    if sink_type == "prompt_injection_sink":
        template = templates.get("dataflow_prompt_injection", {})
        return ValidationPlan(
            item.id, item.asset_type, "review_only",
            "traced to an LLM call -- see this file's own 'llm' capability hint plan for whether the "
            "correlated endpoint is executable",
            control_test=template.get("control_test"), success_criteria=template.get("success_criteria"),
        )
    return ValidationPlan(
        item.id, item.asset_type, "review_only",
        f"sink category '{sink_type}' has no automated live prober in this project yet "
        "(nuclei/dalfox target the web/XSS surface, not this specifically) -- manual review recommended",
    )


def _plan_auth(item: AttackSurfaceItem, templates: dict[str, dict[str, object]]) -> ValidationPlan:
    template = templates.get("auth", {})
    detected = bool(item.metadata.get("detected"))
    reason = (
        "auth guard presence is a static heuristic and must be confirmed against a real account before "
        "drawing conclusions"
        if detected
        else "no recognized auth guard found -- must be confirmed live (unauthenticated request) before "
        "treating this route as unauthenticated, since middleware/framework defaults aren't visible statically"
    )
    return ValidationPlan(
        item.id, item.asset_type, "review_only", reason,
        required_context=list(template.get("required_context", [])),
        control_test=template.get("control_test"), success_criteria=template.get("success_criteria"),
    )


def _unsupported(item: AttackSurfaceItem, reason: str) -> ValidationPlan:
    return ValidationPlan(item.id, item.asset_type, "unsupported", reason)
