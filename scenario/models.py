from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ScenarioStep:
    """One step of a Scenario.

    session_ref names a *scenario-local* session slot, not a real target
    session id -- steps sharing a session_ref run in the same target-side
    session (multi-turn continuity), while steps with different refs run
    in genuinely separate sessions (cross-session workflows, e.g. "leak
    something as user A, then probe whether user B's session can see
    it"), something a single testcase's session_strategy cannot express
    since it only ever threads one session through a run.

    prompt may reference {{PREV_RESPONSE}} (the immediately preceding
    step's response text, regardless of session) or {{STEP:<step_id>}}
    (a specific earlier step's response text by id).
    """

    id: str
    prompt: str
    session_ref: str = "default"
    category: str = "scenario"
    judges: list[str] = field(default_factory=lambda: ["rule"])


@dataclass(frozen=True)
class Scenario:
    id: str
    name: str
    steps: list[ScenarioStep]
    description: str = ""


@dataclass(frozen=True)
class StepResult:
    step_id: str
    session_ref: str
    prompt: str
    response_text: str
    judgement_passed: bool
    judgement_reason: str
    judgement_score: float

    def to_dict(self) -> dict[str, object]:
        return {
            "step_id": self.step_id,
            "session_ref": self.session_ref,
            "prompt": self.prompt,
            "response_text": self.response_text,
            "judgement_passed": self.judgement_passed,
            "judgement_reason": self.judgement_reason,
            "judgement_score": self.judgement_score,
        }


@dataclass
class ScenarioResult:
    scenario_id: str
    run_id: str
    steps: list[StepResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "scenario_id": self.scenario_id,
            "run_id": self.run_id,
            "any_step_flagged": any(step.judgement_passed for step in self.steps),
            "steps": [step.to_dict() for step in self.steps],
        }
