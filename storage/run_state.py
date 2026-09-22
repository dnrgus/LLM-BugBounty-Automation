from __future__ import annotations

from dataclasses import dataclass

from core.checkpoint import ConfigFingerprintMismatchError
from core.models import utc_now
from storage.sqlite import SQLiteStore


@dataclass(frozen=True)
class ResumeDecision:
    """Whether a run_id is a fresh start or a genuine resume, and (if a
    resume) which step ids already completed and must not be re-run."""

    is_resume: bool
    completed_step_ids: frozenset[str]


class RunStateStore:
    """P3.4-1 (roadmap v3.4.0 Production Hardening): tracks, for a
    resumable run_id, its configuration fingerprint and which step ids
    (e.g. testcase ids) have already completed -- so a process killed
    mid-run and restarted with the same run_id skips everything that
    already finished instead of re-running the whole scan.

    A thin, additive layer on top of SQLiteStore: two new tables,
    created idempotently (create table if not exists) the same way
    every other table in storage/sqlite.py is. Nothing here is wired
    into a pipeline unless that pipeline is explicitly given a
    resume_run_id -- every existing call site that never passes one is
    completely unaffected.
    """

    def __init__(self, store: SQLiteStore):
        self.store = store

    def initialize(self) -> None:
        with self.store.connect() as conn:
            conn.executescript(
                """
                create table if not exists run_state (
                  run_id text primary key,
                  config_fingerprint text not null,
                  status text not null,
                  created_at text not null,
                  updated_at text not null
                );
                create table if not exists run_state_steps (
                  run_id text not null,
                  step_id text not null,
                  updated_at text not null,
                  primary key (run_id, step_id)
                );
                """
            )

    def start_or_resume(self, run_id: str, config_fingerprint: str) -> ResumeDecision:
        """Call once at the start of a resumable run. Raises
        ConfigFingerprintMismatchError if `run_id` already exists with a
        *different* config_fingerprint -- the caller must not proceed as
        though this were either a clean resume or a fresh start.
        """
        self.initialize()
        with self.store.connect() as conn:
            row = conn.execute(
                "select config_fingerprint, status from run_state where run_id = ?", (run_id,)
            ).fetchone()
            now = utc_now()
            if row is None:
                conn.execute(
                    "insert into run_state values (?, ?, 'in_progress', ?, ?)",
                    (run_id, config_fingerprint, now, now),
                )
                return ResumeDecision(is_resume=False, completed_step_ids=frozenset())

            if row["config_fingerprint"] != config_fingerprint:
                raise ConfigFingerprintMismatchError(
                    f"run_id {run_id!r} was previously started with a different configuration -- "
                    "refusing to resume with a changed configuration"
                )

            completed = {
                r["step_id"]
                for r in conn.execute("select step_id from run_state_steps where run_id = ?", (run_id,)).fetchall()
            }
            conn.execute("update run_state set status = 'in_progress', updated_at = ? where run_id = ?", (now, run_id))
            return ResumeDecision(is_resume=True, completed_step_ids=frozenset(completed))

    def mark_step_completed(self, run_id: str, step_id: str) -> None:
        with self.store.connect() as conn:
            conn.execute(
                "insert or replace into run_state_steps values (?, ?, ?)",
                (run_id, step_id, utc_now()),
            )

    def mark_run_completed(self, run_id: str) -> None:
        with self.store.connect() as conn:
            conn.execute(
                "update run_state set status = 'completed', updated_at = ? where run_id = ?",
                (utc_now(), run_id),
            )
