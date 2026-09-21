from __future__ import annotations

from core.models import Run, SessionState, Trace


class SessionManager:
    def __init__(self, target_id: str):
        self.target_id = target_id

    def create(self, run: Run) -> SessionState:
        return SessionState(run_id=run.id, target_id=self.target_id)

    def session_for_trace(self, trace: Trace) -> str:
        return trace.id
