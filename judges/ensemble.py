from __future__ import annotations

from core.models import Judgement
from judges.signals import JudgeSignal, default_judges
from testcase.schema import Testcase


class JudgeEnsemble:
    def __init__(self, enabled: list[str]):
        self.enabled = enabled
        self.judges = default_judges()

    @classmethod
    def default(cls) -> "JudgeEnsemble":
        return cls(["rule", "regex", "canary"])

    def judge(self, run_id: str, testcase: Testcase, response_text: str) -> Judgement:
        signals = [self._judge_one(name, response_text) for name in testcase.judges if name in self.enabled]
        if not signals:
            signals = [JudgeSignal("none", False, 0.0, "no enabled judges")]
        passed = any(signal.passed for signal in signals)
        score = max(signal.score for signal in signals)
        reason = "; ".join(f"{signal.name}: {signal.reason}" for signal in signals)
        return Judgement(
            run_id=run_id,
            testcase_id=testcase.id,
            judge_type="ensemble",
            passed=passed,
            score=score,
            reason=reason,
        )

    def _judge_one(self, name: str, text: str) -> JudgeSignal:
        judge = self.judges.get(name)
        if judge is not None:
            return judge.evaluate(text)
        return JudgeSignal(name, False, 0.0, "unsupported judge")
