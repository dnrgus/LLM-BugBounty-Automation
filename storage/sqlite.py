from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from pathlib import Path

from core.models import (
    Asset,
    Endpoint,
    Evidence,
    Finding,
    FindingStatus,
    Judgement,
    MutationRecord,
    PromptRecord,
    ReportRecord,
    Reproduction,
    RequestRecord,
    ResponseRecord,
    Run,
    ExecutionCheckpoint,
    SessionState,
    StoredTestcase,
    Target,
    Trace,
    TraceEvent,
)
from storage.artifacts import sha256_file
from validation.contract import ValidationResult, ValidationTask


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
                create table if not exists assets (
                  id text primary key,
                  run_id text not null,
                  target_id text not null,
                  domain text not null,
                  source text not null,
                  in_scope integer not null,
                  created_at text not null
                );
                create table if not exists endpoints (
                  id text primary key,
                  run_id text not null,
                  target_id text not null,
                  url text not null,
                  method text not null,
                  source text not null,
                  status_code integer,
                  classification text not null,
                  in_scope integer not null,
                  metadata text not null,
                  created_at text not null
                );
                create table if not exists sessions (
                  id text primary key,
                  run_id text not null,
                  target_id text not null,
                  status text not null,
                  created_at text not null
                );
                create table if not exists checkpoints (
                  id text primary key,
                  run_id text not null,
                  trace_id text not null,
                  testcase_id text not null,
                  idempotency_key text not null unique,
                  status text not null,
                  attempts integer not null,
                  error text,
                  updated_at text not null
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
                  evidence_ref text not null,
                  reproduction_spec text,
                  origin text,
                  static_candidate_id text,
                  validation_task_ids text,
                  validation_status text
                );
                create table if not exists evidence (
                  id text primary key,
                  run_id text not null,
                  kind text not null,
                  path text not null,
                  sha256 text not null,
                  sanitized integer not null,
                  raw_path text,
                  raw_sha256 text
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
                create table if not exists validation_tasks (
                  id text primary key,
                  candidate_id text not null,
                  validator_type text not null,
                  prerequisites text not null,
                  risk_level text not null,
                  required_sessions integer not null,
                  budget_hint text not null,
                  status text not null,
                  created_at text not null,
                  updated_at text not null
                );
                create table if not exists validation_results (
                  id text primary key,
                  task_id text not null,
                  status text not null,
                  confidence real not null,
                  evidence_refs text not null,
                  observations text not null,
                  created_at text not null
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
        # P3.4-1: "insert or ignore" makes re-inserting the same Run (a
        # resumed run reuses its run_id across process restarts) an
        # idempotent no-op instead of an integrity-constraint error --
        # never a behavior change for a fresh run.id, which is never
        # inserted twice.
        with self.connect() as conn:
            conn.execute(
                "insert or ignore into runs values (:id, :target_id, :policy_hash, :fingerprint, :created_at)",
                asdict(run),
            )

    def insert_asset(self, asset: Asset) -> None:
        data = asdict(asset)
        data["in_scope"] = int(asset.in_scope)
        with self.connect() as conn:
            conn.execute(
                "insert into assets values (:id, :run_id, :target_id, :domain, :source, :in_scope, :created_at)",
                data,
            )

    def insert_endpoint(self, endpoint: Endpoint) -> None:
        data = asdict(endpoint)
        data["in_scope"] = int(endpoint.in_scope)
        data["metadata"] = _json(data["metadata"])
        with self.connect() as conn:
            conn.execute(
                """
                insert into endpoints values (
                  :id, :run_id, :target_id, :url, :method, :source,
                  :status_code, :classification, :in_scope, :metadata, :created_at
                )
                """,
                data,
            )

    def insert_session(self, session: SessionState) -> None:
        with self.connect() as conn:
            conn.execute(
                "insert or replace into sessions values (:id, :run_id, :target_id, :status, :created_at)",
                asdict(session),
            )

    def upsert_checkpoint(self, checkpoint: ExecutionCheckpoint) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                insert into checkpoints values (
                  :id, :run_id, :trace_id, :testcase_id, :idempotency_key,
                  :status, :attempts, :error, :updated_at
                )
                on conflict(idempotency_key) do update set
                  status = excluded.status,
                  attempts = excluded.attempts,
                  error = excluded.error,
                  updated_at = excluded.updated_at
                """,
                asdict(checkpoint),
            )

    def get_checkpoint(self, idempotency_key: str) -> sqlite3.Row | None:
        with self.connect() as conn:
            return conn.execute(
                "select * from checkpoints where idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()

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
        # mutation.id is a hash of (strategy, prompt), not a random id, so the
        # same mutation legitimately reappears across separate runs against
        # the same store (e.g. re-scanning a target) -- upsert rather than
        # crash on the resulting unique-constraint collision.
        with self.connect() as conn:
            conn.execute(
                "insert or replace into mutations values (:id, :testcase_id, :strategy, :prompt_hash, :parent_mutation_id, :generation)",
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
        data["reproduction_spec"] = _json(finding.reproduction_spec)
        data["origin"] = _json(finding.origin)
        data["validation_task_ids"] = _json(finding.validation_task_ids)
        with self.connect() as conn:
            columns = {row["name"] for row in conn.execute("pragma table_info(findings)").fetchall()}
            if "reproduction_spec" not in columns:
                for key in ("reproduction_spec", "origin", "static_candidate_id", "validation_task_ids", "validation_status"):
                    data.pop(key, None)
                conn.execute(
                    "insert into findings(id, run_id, testcase_id, title, category, status, confidence, severity, evidence_ref) "
                    "values (:id, :run_id, :testcase_id, :title, :category, :status, :confidence, :severity, :evidence_ref)",
                    data,
                )
                return
            if "origin" not in columns:
                for key in ("origin", "static_candidate_id", "validation_task_ids", "validation_status"):
                    data.pop(key, None)
                conn.execute(
                    "insert into findings(id, run_id, testcase_id, title, category, status, confidence, severity, evidence_ref, reproduction_spec) "
                    "values (:id, :run_id, :testcase_id, :title, :category, :status, :confidence, :severity, :evidence_ref, :reproduction_spec)",
                    data,
                )
                return
            conn.execute(
                "insert into findings values (:id, :run_id, :testcase_id, :title, :category, :status, :confidence, :severity, "
                ":evidence_ref, :reproduction_spec, :origin, :static_candidate_id, :validation_task_ids, :validation_status)",
                data,
            )

    def _row_to_finding(self, row: sqlite3.Row, columns: set[str]) -> Finding:
        reproduction_spec = {"type": "single"}
        if "reproduction_spec" in columns and row["reproduction_spec"]:
            reproduction_spec = json.loads(row["reproduction_spec"])
        origin = ["dynamic"]
        if "origin" in columns and row["origin"]:
            origin = json.loads(row["origin"])
        validation_task_ids: list[str] = []
        if "validation_task_ids" in columns and row["validation_task_ids"]:
            validation_task_ids = json.loads(row["validation_task_ids"])
        return Finding(
            id=row["id"],
            run_id=row["run_id"],
            testcase_id=row["testcase_id"],
            title=row["title"],
            category=row["category"],
            status=FindingStatus(row["status"]),
            confidence=row["confidence"],
            severity=row["severity"],
            evidence_ref=row["evidence_ref"],
            reproduction_spec=reproduction_spec,
            origin=origin,
            static_candidate_id=row["static_candidate_id"] if "static_candidate_id" in columns else None,
            validation_task_ids=validation_task_ids,
            validation_status=row["validation_status"] if "validation_status" in columns else None,
        )

    def list_findings(self, run_ids: list[str]) -> list[Finding]:
        if not run_ids:
            return []
        placeholders = ",".join("?" for _ in run_ids)
        with self.connect() as conn:
            columns = {row["name"] for row in conn.execute("pragma table_info(findings)").fetchall()}
            rows = conn.execute(f"select * from findings where run_id in ({placeholders})", run_ids).fetchall()
        return [self._row_to_finding(row, columns) for row in rows]

    def update_finding_reproduction_spec(self, finding_id: str, reproduction_spec: dict[str, object]) -> None:
        """P3.3-3 (roadmap v3.3.0): lets validation/executor.py tag an
        already-inserted Finding's reproduction_spec with dynamic-
        validation provenance (origin=[static,dynamic], the static
        candidate it came from) after the fact, without needing a
        second insert path. No-op on an older schema missing the
        column, same fallback convention as insert_finding.
        """
        with self.connect() as conn:
            columns = {row["name"] for row in conn.execute("pragma table_info(findings)").fetchall()}
            if "reproduction_spec" not in columns:
                return
            conn.execute(
                "update findings set reproduction_spec = ? where id = ?",
                (_json(reproduction_spec), finding_id),
            )

    def get_finding(self, finding_id: str) -> Finding | None:
        with self.connect() as conn:
            columns = {row["name"] for row in conn.execute("pragma table_info(findings)").fetchall()}
            row = conn.execute("select * from findings where id = ?", (finding_id,)).fetchone()
        if row is None:
            return None
        return self._row_to_finding(row, columns)

    def get_latest_prompt_text(self, testcase_id: str) -> str | None:
        with self.connect() as conn:
            row = conn.execute(
                "select text from prompts where testcase_id = ? order by rowid desc limit 1",
                (testcase_id,),
            ).fetchone()
        return row["text"] if row is not None else None

    def insert_reproduction(self, reproduction: Reproduction) -> None:
        data = asdict(reproduction)
        data["control_passed"] = int(reproduction.control_passed)
        data["status"] = reproduction.status.value
        with self.connect() as conn:
            conn.execute(
                "insert into reproductions values (:id, :finding_id, :attempts, :successes, :control_passed, :status)",
                data,
            )

    def record_evidence(self, run_id: str, kind: str, path: Path, raw_path: Path | None = None) -> Evidence:
        evidence = Evidence(
            run_id=run_id,
            kind=kind,
            path=str(path),
            sha256=sha256_file(path),
            sanitized=True,
            raw_path=str(raw_path) if raw_path is not None else None,
            raw_sha256=sha256_file(raw_path) if raw_path is not None and Path(raw_path).exists() else None,
        )
        data = {**asdict(evidence), "sanitized": 1}
        with self.connect() as conn:
            columns = {row["name"] for row in conn.execute("pragma table_info(evidence)").fetchall()}
            if "raw_path" not in columns:
                data.pop("raw_path")
                data.pop("raw_sha256")
                conn.execute(
                    "insert into evidence(id, run_id, kind, path, sha256, sanitized) "
                    "values (:id, :run_id, :kind, :path, :sha256, :sanitized)",
                    data,
                )
                return evidence
            conn.execute(
                "insert into evidence values (:id, :run_id, :kind, :path, :sha256, :sanitized, :raw_path, :raw_sha256)",
                data,
            )
        return evidence

    def list_evidence(self, run_id: str) -> list[sqlite3.Row]:
        """P3.4-3: raw material for reporting/integrity.py's per-run
        manifest -- every Evidence row recorded under `run_id`, in a
        stable order (so the manifest is deterministic)."""
        with self.connect() as conn:
            return conn.execute("select * from evidence where run_id = ? order by id", (run_id,)).fetchall()

    def record_report(self, run_id: str, path: Path) -> None:
        report = ReportRecord(run_id=run_id, path=str(path))
        with self.connect() as conn:
            columns = {row["name"] for row in conn.execute("pragma table_info(reports)").fetchall()}
            if "kind" not in columns:
                conn.execute("insert into reports(run_id, path) values (?, ?)", (run_id, str(path)))
                return
            conn.execute("insert into reports values (:id, :run_id, :path, :kind)", asdict(report))

    def list_reports(self, run_id: str) -> list[str]:
        """P3.4-1: lets a resumed run report every report path ever
        recorded under this run_id, cumulative across process restarts,
        not just the ones this particular invocation wrote."""
        with self.connect() as conn:
            rows = conn.execute("select path from reports where run_id = ?", (run_id,)).fetchall()
        return [row["path"] for row in rows]

    def upsert_validation_task(self, task: ValidationTask) -> None:
        """P4.1-A (roadmap v4.1.0 Dynamic Validation Expansion): persists
        a ValidationTask's current state -- "insert or replace" so
        repeated calls as a task moves through its lifecycle
        (transition()) just update the same row."""
        data = task.to_dict()
        data["prerequisites"] = _json(data["prerequisites"])
        data["budget_hint"] = _json(data["budget_hint"])
        with self.connect() as conn:
            conn.execute(
                "insert or replace into validation_tasks values "
                "(:id, :candidate_id, :validator_type, :prerequisites, :risk_level, :required_sessions, "
                ":budget_hint, :status, :created_at, :updated_at)",
                data,
            )

    def get_validation_task(self, task_id: str) -> ValidationTask | None:
        with self.connect() as conn:
            row = conn.execute("select * from validation_tasks where id = ?", (task_id,)).fetchone()
        if row is None:
            return None
        return ValidationTask.from_dict(
            {
                **dict(row),
                "prerequisites": json.loads(row["prerequisites"]),
                "budget_hint": json.loads(row["budget_hint"]),
            }
        )

    def insert_validation_result(self, result: ValidationResult) -> None:
        data = result.to_dict()
        data["evidence_refs"] = _json(data["evidence_refs"])
        data["observations"] = _json(data["observations"])
        with self.connect() as conn:
            conn.execute(
                "insert into validation_results values (:id, :task_id, :status, :confidence, :evidence_refs, "
                ":observations, :created_at)",
                data,
            )

    def list_validation_results(self, task_id: str) -> list[ValidationResult]:
        with self.connect() as conn:
            rows = conn.execute(
                "select * from validation_results where task_id = ? order by rowid", (task_id,)
            ).fetchall()
        return [
            ValidationResult.from_dict(
                {**dict(row), "evidence_refs": json.loads(row["evidence_refs"]), "observations": json.loads(row["observations"])}
            )
            for row in rows
        ]
