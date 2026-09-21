from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from pathlib import Path

from core.models import (
    Evidence,
    Finding,
    Judgement,
    MutationRecord,
    PromptRecord,
    ReportRecord,
    Reproduction,
    RequestRecord,
    ResponseRecord,
    Run,
    StoredTestcase,
    Target,
    Trace,
    TraceEvent,
)
from storage.artifacts import sha256_file


def _json(data: object) -> str:
    return json.dumps(data, sort_keys=True, default=str)


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
                create table if not exists targets (
                  id text primary key,
                  kind text not null,
                  base_url text not null,
                  capabilities text not null,
                  metadata text not null,
                  created_at text not null
                );
                create table if not exists testcases (
                  id text primary key,
                  name text not null,
                  category text not null,
                  content_hash text not null,
                  frameworks text not null,
                  version text not null
                );
                create table if not exists prompts (
                  id text primary key,
                  testcase_id text not null,
                  prompt_hash text not null,
                  text text not null,
                  mutation_id text
                );
                create table if not exists mutations (
                  id text primary key,
                  testcase_id text not null,
                  strategy text not null,
                  prompt_hash text not null,
                  parent_mutation_id text,
                  generation integer not null
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
                create table if not exists requests (
                  id text primary key,
                  run_id text not null,
                  trace_id text not null,
                  testcase_id text not null,
                  prompt_hash text not null,
                  artifact_ref text,
                  latency_ms integer,
                  token_count integer,
                  cost_usd real,
                  metadata text not null,
                  created_at text not null
                );
                create table if not exists responses (
                  id text primary key,
                  request_id text not null,
                  trace_id text not null,
                  status_code integer not null,
                  artifact_ref text,
                  latency_ms integer,
                  token_count integer,
                  metadata text not null,
                  created_at text not null
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
                create table if not exists reproductions (
                  id text primary key,
                  finding_id text not null,
                  attempts integer not null,
                  successes integer not null,
                  control_passed integer not null,
                  status text not null
                );
                create table if not exists reports (
                  id text primary key,
                  run_id text not null,
                  path text not null,
                  kind text not null
                );
                """
            )

    def insert_target(self, target: Target) -> None:
        data = asdict(target)
        data["capabilities"] = _json(data["capabilities"])
        data["metadata"] = _json(data["metadata"])
        with self.connect() as conn:
            conn.execute(
                "insert or replace into targets values (:id, :kind, :base_url, :capabilities, :metadata, :created_at)",
                data,
            )

    def insert_run(self, run: Run) -> None:
        with self.connect() as conn:
            conn.execute(
                "insert into runs values (:id, :target_id, :policy_hash, :fingerprint, :created_at)",
                asdict(run),
            )

    def insert_testcase(self, testcase: StoredTestcase) -> None:
        data = asdict(testcase)
        data["frameworks"] = _json(data["frameworks"])
        with self.connect() as conn:
            conn.execute(
                "insert or replace into testcases values (:id, :name, :category, :content_hash, :frameworks, :version)",
                data,
            )

    def insert_prompt(self, prompt: PromptRecord) -> None:
        with self.connect() as conn:
            conn.execute(
                "insert into prompts values (:id, :testcase_id, :prompt_hash, :text, :mutation_id)",
                asdict(prompt),
            )

    def insert_mutation(self, mutation: MutationRecord) -> None:
        with self.connect() as conn:
            conn.execute(
                "insert into mutations values (:id, :testcase_id, :strategy, :prompt_hash, :parent_mutation_id, :generation)",
                asdict(mutation),
            )

    def insert_trace(self, trace: Trace) -> None:
        with self.connect() as conn:
            conn.execute("insert into traces values (:id, :run_id, :testcase_id, :created_at)", asdict(trace))

    def insert_event(self, event: TraceEvent) -> None:
        data = asdict(event)
        data["metadata"] = _json(data["metadata"])
        with self.connect() as conn:
            conn.execute(
                "insert into events values (:id, :trace_id, :sequence, :event_type, :timestamp, :artifact_ref, :metadata)",
                data,
            )

    def list_events(self, trace_id: str) -> list[sqlite3.Row]:
        with self.connect() as conn:
            rows = conn.execute(
                "select * from events where trace_id = ? order by sequence asc",
                (trace_id,),
            ).fetchall()
        return list(rows)

    def insert_request(self, request: RequestRecord) -> None:
        data = asdict(request)
        data["metadata"] = _json(data["metadata"])
        with self.connect() as conn:
            conn.execute(
                """
                insert into requests values (
                  :id, :run_id, :trace_id, :testcase_id, :prompt_hash,
                  :artifact_ref, :latency_ms, :token_count, :cost_usd,
                  :metadata, :created_at
                )
                """,
                data,
            )

    def insert_response(self, response: ResponseRecord) -> None:
        data = asdict(response)
        data["metadata"] = _json(data["metadata"])
        with self.connect() as conn:
            conn.execute(
                """
                insert into responses values (
                  :id, :request_id, :trace_id, :status_code, :artifact_ref,
                  :latency_ms, :token_count, :metadata, :created_at
                )
                """,
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

    def insert_reproduction(self, reproduction: Reproduction) -> None:
        data = asdict(reproduction)
        data["control_passed"] = int(reproduction.control_passed)
        data["status"] = reproduction.status.value
        with self.connect() as conn:
            conn.execute(
                "insert into reproductions values (:id, :finding_id, :attempts, :successes, :control_passed, :status)",
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
        report = ReportRecord(run_id=run_id, path=str(path))
        with self.connect() as conn:
            columns = {row["name"] for row in conn.execute("pragma table_info(reports)").fetchall()}
            if "kind" not in columns:
                conn.execute("insert into reports(run_id, path) values (?, ?)", (run_id, str(path)))
                return
            conn.execute("insert into reports values (:id, :run_id, :path, :kind)", asdict(report))
