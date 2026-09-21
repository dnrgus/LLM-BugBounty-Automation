import asyncio
from pathlib import Path

from core.models import Run
from core.orchestrator import _session_id_for, run_sample_pipeline
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from targets.base import TargetResponse
from targets.fake import FakeLLMTarget
from testcase.schema import Testcase


def _policy() -> PolicyEngine:
    return PolicyEngine.from_yaml("config/scope.example.yaml")


def test_session_id_for_per_testcase_defaults_to_executor_fallback() -> None:
    run = Run(target_id="t", policy_hash="h", fingerprint="f")
    case = Testcase(id="X", name="X", category="prompt_injection", requires=["chat"], prompt="p", judges=["rule"])
    assert _session_id_for(run, "target-1", case) is None


def test_session_id_for_shared_suite_is_scoped_to_run_and_category() -> None:
    run = Run(target_id="t", policy_hash="h", fingerprint="f")
    case_a = Testcase(
        id="A", name="A", category="prompt_injection", requires=["chat"], prompt="p",
        judges=["rule"], session_strategy="shared_suite",
    )
    case_b = Testcase(
        id="B", name="B", category="prompt_injection", requires=["chat"], prompt="p2",
        judges=["rule"], session_strategy="shared_suite",
    )
    case_other_category = Testcase(
        id="C", name="C", category="rag_security", requires=["chat"], prompt="p3",
        judges=["rule"], session_strategy="shared_suite",
    )
    assert _session_id_for(run, "target-1", case_a) == _session_id_for(run, "target-1", case_b)
    assert _session_id_for(run, "target-1", case_a) != _session_id_for(run, "target-1", case_other_category)


def test_session_id_for_persistent_is_scoped_to_target_not_run() -> None:
    run_1 = Run(target_id="t", policy_hash="h", fingerprint="f1")
    run_2 = Run(target_id="t", policy_hash="h", fingerprint="f2")
    case = Testcase(
        id="A", name="A", category="prompt_injection", requires=["chat"], prompt="p",
        judges=["rule"], session_strategy="persistent",
    )
    # same target + category -> same session even across two separate runs
    assert _session_id_for(run_1, "target-1", case) == _session_id_for(run_2, "target-1", case)
    assert _session_id_for(run_1, "target-1", case) != _session_id_for(run_1, "target-2", case)


class SessionRecordingTarget(FakeLLMTarget):
    """Records the session id every send() call actually receives, so the
    test can assert whether two testcases genuinely shared one target-side
    session -- not just that _session_id_for() computed matching strings."""

    def __init__(self) -> None:
        super().__init__()
        self.sessions_seen: list[str | None] = []

    async def send(self, prompt: str, session: str | None = None) -> TargetResponse:
        self.sessions_seen.append(session)
        return await super().send(prompt, session=session)


def test_shared_suite_testcases_genuinely_land_in_the_same_target_session(tmp_path: Path, monkeypatch) -> None:
    import core.orchestrator as orchestrator_module

    target = SessionRecordingTarget()
    monkeypatch.setattr(orchestrator_module, "create_target", lambda kind, config=None: target)

    testcases = [
        Testcase(
            id="SHARED-A", name="Shared A", category="prompt_injection", requires=["chat"],
            prompt="first turn", judges=["rule"], session_strategy="shared_suite",
        ),
        Testcase(
            id="SHARED-B", name="Shared B", category="prompt_injection", requires=["chat"],
            prompt="second turn", judges=["rule"], session_strategy="shared_suite",
        ),
    ]
    store = SQLiteStore(tmp_path / "shared_suite.sqlite")
    asyncio.run(run_sample_pipeline(_policy(), testcases, store, target_kind="fake-llm"))

    # rule judge passes both testcases, so each one's main execute() call is
    # followed by Reproducer.reproduce() attempts, which intentionally use
    # their own fresh per-attempt sessions -- only the two *main* executions
    # (the first send() per testcase) should land in the shared session.
    main_sessions = [target.sessions_seen[0], target.sessions_seen[3]]
    assert main_sessions[0] == main_sessions[1]
    assert main_sessions[0] is not None
    assert main_sessions[0].endswith(":prompt_injection")
