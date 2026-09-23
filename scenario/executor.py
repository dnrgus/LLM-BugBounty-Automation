from __future__ import annotations

import re

from core.models import Run, Trace
from executor.runner import Executor
from judges.ensemble import JudgeEnsemble
from scenario.models import Scenario, ScenarioResult, StepResult
from storage.sqlite import SQLiteStore
from testcase.schema import Testcase

_PREV_RESPONSE_TOKEN = "{{PREV_RESPONSE}}"
_STEP_TOKEN_RE = re.compile(r"\{\{STEP:([^}]+)\}\}")


async def run_scenario(
    scenario: Scenario,
    run: Run,
    executor: Executor,
    judges: JudgeEnsemble,
    store: SQLiteStore,
    target_url: str,
) -> ScenarioResult:
    """U9 Scenario Engine (design doc section 11): executes a named,
    ordered sequence of steps through the *existing* Executor and
    JudgeEnsemble, unmodified -- this runs alongside
    core/orchestrator.py's single-testcase _process_case path, not in
    place of it.

    Each step optionally names its own session_ref, so a Scenario can
    model a genuinely cross-session workflow (leak something in one
    session, then probe whether a second, separate session can retrieve
    it) -- something the existing per-testcase session_strategy cannot
    express, since it only ever threads one session through a run.
    Steps that share a session_ref get the same target-side session
    (multi-turn continuity); steps with different refs get separate
    ones. A step's prompt may reference {{PREV_RESPONSE}} (the prior
    step's response, regardless of session) or {{STEP:<id>}} (a specific
    earlier step's response by id), letting a later step act on what an
    earlier one produced.

    Deliberately out of scope here: Finding/evidence-bundle/report
    creation and reproduction. Those exist for the single-testcase path
    (_process_case) and reusing them for a multi-step, multi-session,
    templated scenario is a real design question of its own (what does
    "reproduce" mean for a whole sequence?) left for a later wiring
    phase, consistent with not combining structure change with feature
    expansion in one phase.
    """
    session_slots: dict[str, str] = {}
    step_responses: dict[str, str] = {}
    results: list[StepResult] = []

    for step in scenario.steps:
        session_id = session_slots.setdefault(
            step.session_ref, f"scenario_{run.id}_{scenario.id}_{step.session_ref}"
        )
        prompt = _render_prompt(step.prompt, step_responses)
        testcase = Testcase(
            id=f"{scenario.id}:{step.id}",
            name=f"{scenario.name} / {step.id}",
            category=step.category,
            requires=[],
            prompt=prompt,
            judges=step.judges,
        )
        trace = Trace(run_id=run.id, testcase_id=testcase.id)
        store.insert_trace(trace)
        response = await executor.execute(
            run=run, trace=trace, testcase=testcase, url=target_url, session_id=session_id
        )
        judgement = judges.judge(run.id, testcase, response.text, trace_events=response.trace_events)
        store.insert_judgement(judgement)
        step_responses[step.id] = response.text
        results.append(
            StepResult(
                step_id=step.id,
                session_ref=step.session_ref,
                prompt=prompt,
                response_text=response.text,
                judgement_passed=judgement.passed,
                judgement_reason=judgement.reason,
                judgement_score=judgement.score,
            )
        )

    return ScenarioResult(scenario_id=scenario.id, run_id=run.id, steps=results)


def _render_prompt(template: str, step_responses: dict[str, str]) -> str:
    rendered = template
    if _PREV_RESPONSE_TOKEN in rendered and step_responses:
        rendered = rendered.replace(_PREV_RESPONSE_TOKEN, next(reversed(step_responses.values())))
    return _STEP_TOKEN_RE.sub(lambda match: step_responses.get(match.group(1), match.group(0)), rendered)
