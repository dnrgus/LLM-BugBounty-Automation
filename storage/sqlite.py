from __future__ import annotations

import sqlite3
from dataclasses import asdict
from pathlib import Path

from core.models import Evidence, Finding, Judgement, Run, Trace, TraceEvent
from storage.artifacts import sha256_file


class SQLiteStore:
    def __init__(self, path: Path | str):
        self.path = Path(path)

    def connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def initialize(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                create table if not exists runs (
                  id text primary key,
                  target_id text not null,
                  policy_hash text not null,
                  fingerprint text not null,
                  created_at text not null
                );
                create table if not exists traces (
                  id text primary key,
                  run_id text not null,
                  testcase_id text not null,
                  created_at text not null
                );
                create table if not exists events (
                  id text primary key,
                  trace_id text not null,
                  sequence integer not null,
                  event_type text not null,
                  timestamp text not null,
                  artifact_ref text,
                  metadata text not null
                );
                create table if not exists judgements (
                  id text primary key,
                  run_id text not null,
                  testcase_id text not null,
                  judge_type text not null,
                  passed integer not null,
                  score real not null,
                  reason text not null,
                  evidence_ref text
                );
                create table if not exists findings (
                  id text primary key,
                  run_id text not null,
                  testcase_id text not null,
                  title text not null,
                  category text not null,
                  status text not null,
                  confidence real not null,
                  severity text not null,
                  evidence_ref text not null
                );
                create table if not exists evidence (
                  id text primary key,
                  run_id text not null,
                  kind text not null,
                  path text not null,
                  sha256 text not null,
                  sanitized integer not null
                );
                create table if not exists reports (
                  id integer primary key autoincrement,
                  run_id text not null,
                  path text not null
                );
                """
            )

    def insert_run(self, run: Run) -> None:
        with self.connect() as conn:
            conn.execute(
                "insert into runs values (:id, :target_id, :policy_hash, :fingerprint, :created_at)",
                asdict(run),
            )

    def insert_trace(self, trace: Trace) -> None:
        with self.connect() as conn:
            conn.execute("insert into traces values (:id, :run_id, :testcase_id, :created_at)", asdict(trace))

    def insert_event(self, event: TraceEvent) -> None:
        data = asdict(event)
        data["metadata"] = __import__("json").dumps(data["metadata"], sort_keys=True)
        with self.connect() as conn:
            conn.execute(
                "insert into events values (:id, :trace_id, :sequence, :event_type, :timestamp, :artifact_ref, :metadata)",
                data,
            )

    def insert_judgement(self, judgement: Judgement) -> None:
        data = asdict(judgement)
        data["passed"] = int(judgement.passed)
        with self.connect() as conn:
            conn.execute(
                "insert into judgements values (:id, :run_id, :testcase_id, :judge_type, :passed, :score, :reason, :evidence_ref)",
                data,
            )

    def insert_finding(self, finding: Finding) -> None:
        data = asdict(finding)
        data["status"] = finding.status.value
        with self.connect() as conn:
            conn.execute(
                "insert into findings values (:id, :run_id, :testcase_id, :title, :category, :status, :confidence, :severity, :evidence_ref)",
                data,
            )

    def record_evidence(self, run_id: str, kind: str, path: Path) -> Evidence:
        evidence = Evidence(run_id=run_id, kind=kind, path=str(path), sha256=sha256_file(path), sanitized=True)
        with self.connect() as conn:
            conn.execute(
                "insert into evidence values (:id, :run_id, :kind, :path, :sha256, :sanitized)",
                {**asdict(evidence), "sanitized": 1},
            )
        return evidence

    def record_report(self, run_id: str, path: Path) -> None:
        with self.connect() as conn:
            conn.execute("insert into reports(run_id, path) values (?, ?)", (run_id, str(path)))

