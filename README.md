# LLM-BugBounty-Automation

Automated pipeline for authorized LLM security testing, red teaming,
vulnerability validation, reproduction, evidence collection, and bug bounty
reporting.

This repository is intentionally scope-first and policy-aware. It is designed
for authorized testing only. The current implementation provides the first
working vertical slice:

- CLI entry points for `doctor`, `fingerprint`, `validate-scope`, and
  `sample-run`
- Scope and program policy enforcement before any target action
- Capability-aware YAML testcase loading
- Fake LLM target for offline integration tests
- Trace events, deterministic judges, evidence redaction, and basic reports
- SQLite storage primitives for runs, traces, events, judgements, findings,
  evidence, and reports

## Quick Start

```bash
python -m pip install -e ".[dev]"
python main.py doctor
python main.py validate-scope --url https://ai.example.com/api/chat
python main.py sample-run
pytest
```

`sample-run` uses only the bundled fake target. It does not contact external
services.

## Repository Layout

```text
config/        default pipeline, model, tool, logging, and scope examples
core/          orchestrator, models, events, and fingerprints
scope/         scope and program policy enforcement
targets/       target adapter contract and fake targets
testcase/      YAML testcase schema, loader, selector, and seed suite
executor/      session runner and approval gate
traces/        trace export helpers
judges/        rule, canary, regex, and ensemble judges
storage/       SQLite and artifact helpers
reporting/     evidence redaction and report generation
tests/         unit and integration tests
```

## Safety Model

Every execution must pass both:

1. Scope validation: domain and URL pattern checks.
2. Program policy validation: allowed testing types, rate/concurrency/request
   budget, and high-risk action decisions.

High-risk actions are blocked or simulated by default. Raw evidence, local run
artifacts, private reports, credentials, and environment files are gitignored.

## Milestones

The design document defines these executable milestones:

- `v0.1.0-mvp1`: core validation loop, evidence, and basic reporting
- `v0.2.0-llm-redteam`: Promptfoo/Garak/Mutation/PyRIT integration
- `v0.3.0-discovery`: recon, web security tools, AI discovery, and RAG harness
- `v1.0.0`: stable first release

