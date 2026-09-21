from __future__ import annotations

import re
from dataclasses import dataclass

from judges.ensemble import JudgeEnsemble
from targets.base import TargetAdapter
from testcase.schema import Testcase

_SEGMENT_SPLIT_RE = re.compile(r"(\s+)")


@dataclass(frozen=True)
class MinimalPoC:
    original_prompt: str
    minimized_prompt: str
    removed_segments: list[str]
    attempts: int

    def to_dict(self) -> dict[str, object]:
        reduction_ratio = 0.0
        if self.original_prompt:
            reduction_ratio = round(1 - len(self.minimized_prompt) / len(self.original_prompt), 3)
        return {
            "original_prompt": self.original_prompt,
            "minimized_prompt": self.minimized_prompt,
            "removed_segments": self.removed_segments,
            "reduction_ratio": reduction_ratio,
            "attempts": self.attempts,
        }


async def minimize_poc(
    testcase: Testcase,
    target: TargetAdapter,
    judges: JudgeEnsemble,
    session_prefix: str,
    max_iterations: int = 50,
) -> MinimalPoC:
    """Greedy segment-removal minimization (design doc section 10):

    - split the successful prompt into whitespace-delimited segments
    - drop one segment at a time; keep the drop only if the finding still
      reproduces (fresh session, same judges)
    - repeat until a full pass removes nothing (fixpoint) or max_iterations
      is hit

    This is the doc's literal "제거 -> 확인 -> 확정/복원 -> 반복" description,
    not full ddmin binary-partition search.
    """
    original_prompt = testcase.render_prompt()
    parts = _SEGMENT_SPLIT_RE.split(original_prompt)
    kept = [True] * len(parts)
    removed_segments: list[str] = []
    attempts = 0

    changed = True
    while changed and attempts < max_iterations:
        changed = False
        for index, part in enumerate(parts):
            if not kept[index] or part == "" or part.isspace():
                continue
            kept[index] = False
            candidate = "".join(p for j, p in enumerate(parts) if kept[j]).strip()
            attempts += 1
            if not candidate:
                kept[index] = True
                continue
            session = f"{session_prefix}:minimize:{attempts}"
            await target.reset_session(session)
            response = await target.send(candidate, session=session)
            judgement = judges.judge("minimize", testcase, response.text)
            if judgement.passed:
                removed_segments.append(part)
                changed = True
            else:
                kept[index] = True
            if attempts >= max_iterations:
                break

    minimized_prompt = "".join(p for j, p in enumerate(parts) if kept[j]).strip()
    return MinimalPoC(
        original_prompt=original_prompt,
        minimized_prompt=minimized_prompt,
        removed_segments=removed_segments,
        attempts=attempts,
    )
