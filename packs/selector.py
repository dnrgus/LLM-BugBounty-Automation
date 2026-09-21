from __future__ import annotations

from dataclasses import dataclass

from core.budget import AttackBudget
from live.classify import TargetKind
from packs.registry import DEFAULT_PACKS, AttackPack
from scope.policy import PolicyEngine


@dataclass(frozen=True)
class PackSelection:
    pack: AttackPack
    selected: bool
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "pack_id": self.pack.id,
            "name": self.pack.name,
            "selected": self.selected,
            "reason": self.reason,
            "estimated_request_cost": self.pack.estimated_request_cost,
            "tool_ids": list(self.pack.tool_ids),
        }


def select_packs(
    target_kinds: set[TargetKind],
    policy: PolicyEngine,
    budget: AttackBudget | None = None,
    packs: tuple[AttackPack, ...] = DEFAULT_PACKS,
) -> list[PackSelection]:
    """U6 Pack Selector (design doc section 8): decides which Attack Packs
    apply to a target given its classified capabilities (from U5), Policy
    (does the program's scope config allow this testing category?), and
    Budget (is there estimated room left to run it?) -- before a single
    pack request goes out.

    Every pack is returned, selected or not, with its reason -- so a scan
    report can show *why* a pack that plausibly applies was skipped,
    mirroring how discovery records skipped_out_of_scope rather than
    silently dropping candidates.
    """
    selections: list[PackSelection] = []
    for pack in packs:
        if not (set(pack.applies_to) & target_kinds):
            selections.append(PackSelection(pack, False, "does not apply to this target's classified capabilities"))
            continue

        denied_categories = [
            category for category in pack.testing_categories if not policy.validate_testcase(category).allowed
        ]
        if denied_categories:
            selections.append(
                PackSelection(pack, False, f"policy denies testing categories: {', '.join(denied_categories)}")
            )
            continue

        if budget is not None and budget.max_requests is not None:
            remaining = budget.max_requests - budget.requests_used
            if remaining < pack.estimated_request_cost:
                selections.append(
                    PackSelection(
                        pack,
                        False,
                        f"insufficient budget: needs ~{pack.estimated_request_cost} requests, {remaining} remaining",
                    )
                )
                continue

        selections.append(PackSelection(pack, True, "selected"))
    return selections
