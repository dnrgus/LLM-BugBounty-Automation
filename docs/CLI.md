# CLI Reference (v5.0)

Generated from `cli.build_parser()`; `tests/test_v5_contract.py` fails if a command or option is missing here.

## Exit codes

| code | meaning |
|---|---|
| 0 | success |
| 1 | a gate failed (judge-benchmark, quality-gate, benchmark regression, release-check) |
| 2 | scope denied (validate-scope) or command-line usage error (argparse) |
| 3 | input or configuration error (missing file, invalid schema, unknown id) |
| 130 | cancelled by the user (Ctrl-C) -- resumable where supported |

## Finding states

| state | meaning |
|---|---|
| `candidate` | static or unvalidated signal; no dynamic verdict yet |
| `needs_review` | evidence exists but is not strong enough to confirm (missing context, judge conflict, low confidence) |
| `confirmed` | deterministically judged and reproduced under the recorded conditions |
| `rejected` | tested and not reproduced, or denied as expected |
| `unstable` | reproduced in some but not all attempts |

## Commands

### `doctor`

Check local runtime and optional tools

- `--tools` (default: `config/tools.yaml`)
- `--json` — Print machine-readable doctor output
- `--write-lock` — Write tool_versions.lock.yaml
- `--lockfile` (default: `tool_versions.lock.yaml`)

### `tools`

List supported external tools and their status/purpose

- `--tools` (default: `config/tools.yaml`)
- `--json` — Print machine-readable tool status

### `fingerprint`

Create a reproducibility fingerprint

- `--target-build` (default: `local`)

### `validate-scope`

Validate a URL against scope and policy

- `--scope` (default: `config/scope.example.yaml`)
- `--url` **required**

### `sample-run`

Run the offline fake target pipeline

- `--scope` (default: `config/scope.example.yaml`)
- `--testcases` (default: `testcase/suites/basic.yaml`)
- `--db` (default: `runs/sample.sqlite`)
- `--target` (default: `fake-llm`)
- `--target-config` — YAML target config (see config/targets/*.example.yaml); overrides --target
- `--resume-run-id` — P3.4-1: reuse this run_id and skip its already-completed testcases (from a prior invocation against the same --db) instead of a fresh run. Rejects the call if --testcases/--target/etc. changed since that run_id was started.
- `--semantic-judge-config` — P4.6: opt-in secondary semantic judge (see config/semantic_judge.example.yaml); conflicts or low confidence become needs_review, never confirmed

### `coverage`

Show testcase coverage for a target profile

- `--scope` (default: `config/scope.example.yaml`)
- `--testcases` (default: `testcase/suites/basic.yaml`)
- `--target` (default: `fake-llm`)
- `--target-config` — YAML target config; overrides --target

### `profile`

Probe a target's capabilities (declared config + observed multi-turn behavior)

- `--scope` (default: `config/scope.example.yaml`)
- `--db` (default: `runs/profile.sqlite`)
- `--target` (default: `fake-llm`)
- `--target-config` — YAML target config; overrides --target
- `--no-probe` — Skip active probing; report only the target's declared capabilities

### `reproduce`

Re-run reproduction for a stored finding against a live target, optionally minimizing a PoC

- `finding_id`
- `--scope` (default: `config/scope.example.yaml`)
- `--testcases` (default: `testcase/suites/basic.yaml`)
- `--db` (default: `runs/sample.sqlite`)
- `--target` (default: `fake-llm`)
- `--target-config` — YAML target config; overrides --target
- `--minimize` — If the finding still reproduces, also generate a minimal PoC
- `--auth-contexts` — object access findings from `validate`: tester account YAML (see config/auth_contexts.example.yaml)
- `--attempts` (default: `3`) — object access findings: number of re-runs

### `validate`

Run safe validators over a `scan --source` artifact (scope + method policy gate, object access comparison with tester-owned accounts)

- `--artifact` **required**
- `--base-url` **required** — Base URL of the authorized target
- `--scope` (default: `config/scope.example.yaml`)
- `--db` (default: `runs/validate.sqlite`)
- `--auth-contexts`
- `--key-field` — response field compared (as a hash)

### `report`

Write per-finding reports for a `validate` run

- `--run-id` **required**
- `--db` (default: `runs/validate.sqlite`)
- `--out` (default: `reports/validation`)

### `judge-benchmark`

Run judge benchmark fixtures

- `--benchmark` (default: `benchmarks/judge/baseline.json`)

### `quality-gate`

Score SOURCE MODE against the ground-truth corpus

- `--corpus` (default: `benchmarks/corpus`)
- `--min-recall` (default: `0.85`)
- `--min-precision` (default: `0.85`)

### `benchmark`

Run the benchmark dataset (TP/FP/FN, miss reasons, stability) and compare to a baseline

- `--manifest` (default: `benchmarks/datasets/manifest.yaml`)
- `--timeout` (default: `60.0`) — per-target timeout in seconds
- `--baseline` — fail (exit 1) on regression vs this baseline
- `--write-baseline`
- `--out` — also write the full report JSON here

### `release-check`

Run the v5.0.0 release gate checklist offline (G1-G10); exit 1 if any gate fails

- `--gate` — run only this gate id (repeatable), e.g. G5

### `normalize-tool-output`

Normalize external LLM tool output

- `--tool` **required**
- `--input` **required**
- `--run-id` (default: `run_fixture`)
- `--target-id` (default: `target_fixture`)
- `--version`

### `mutate`

Generate prompt mutations

- `--testcases` (default: `testcase/suites/basic.yaml`)
- `--testcase-id`
- `--strategy`
- `--var`
- `--db`

### `adaptive-plan`

Generate adaptive mutation plans from PyRIT adaptive redteam results

- `--input` **required**
- `--testcases` (default: `testcase/suites/basic.yaml`)
- `--run-id` (default: `run_fixture`)
- `--target-id` (default: `target_fixture`)
- `--version`
- `--db`

### `adaptive-run`

Execute PyRIT-informed adaptive mutations through the Executor/Judge/Reproducer pipeline

- `--scope` (default: `config/scope.example.yaml`)
- `--testcases` (default: `testcase/suites/basic.yaml`)
- `--input` **required**
- `--db` (default: `runs/adaptive.sqlite`)
- `--target` (default: `fake-llm`)
- `--target-config` — YAML target config; overrides --target

### `recon`

Build a scope-revalidated asset map from Subfinder/httpx/Katana/ffuf output

- `--scope` (default: `config/scope.example.yaml`)
- `--run-id` (default: `run_fixture`)
- `--target-id` (default: `target_fixture`)
- `--db` (default: `runs/recon.sqlite`)
- `--subfinder-input`
- `--httpx-input`
- `--katana-input`
- `--ffuf-input`

### `audit`

SOURCE MODE: statically analyze a source tree (routes/inputs/sinks/secrets/LLM integration)

- `path`
- `--max-files` (default: `2000`)

### `correlate`

U8 HYBRID MODE: correlate SOURCE static analysis with a LIVE discovery crawl of the same target (source-detected routes also seen live get a confidence boost and provenance from both sides)

- `source`
- `url`
- `--scope` (default: `config/scope.example.yaml`)
- `--max-pages` (default: `5`)
- `--max-files` (default: `2000`)

### `run-scenario`

U9 Scenario Engine: run a multi-turn/cross-session Scenario suite against a target (runs alongside the normal `sample-run`/`scan` single-testcase path, not in place of it)

- `--scope` (default: `config/scope.example.yaml`)
- `--scenarios` (default: `scenario/suites/basic.yaml`)
- `--db` (default: `runs/scenario.sqlite`)
- `--target` (default: `fake-llm`)
- `--target-config` — Required for --target openai; ignored for the fake targets

### `discover`

LIVE MODE: passively crawl a URL (GET/HEAD only, no attack payloads) for candidate attack surface

- `url`
- `--scope` (default: `config/scope.example.yaml`)
- `--max-pages` (default: `5`)
- `--classify` — U5 Auto Profiler: also classify discovered items into web/api/graphql/llm/rag/agent/websocket candidates
- `--auto-profile` — U5 Auto Profiler: classify, then hand llm/api candidates to the Capability Probe for best-effort verification (implies --classify)
- `--db` (default: `runs/discover.sqlite`)
- `--select-packs` — U6 Pack Selector: classify, then decide which Attack Packs apply given policy and (optional) budget
- `--pack-budget-requests` — Optional request budget ceiling used only for --select-packs' budget check
- `--run-packs` — U7: actually run selected packs (implies --select-packs) -- testcase_suite packs run against --pack-target; external-tool packs (nuclei/dalfox/trufflehog) only run if you supply their results file
- `--testcases` (default: `testcase/suites/basic.yaml`)
- `--pack-target`
- `--pack-target-config`
- `--nuclei-results`
- `--dalfox-results`
- `--trufflehog-results`

### `scan`

LIVE MODE: `scan <url>` discovers/classifies/selects/runs packs end-to-end (P3.1-1). HYBRID MODE: `scan <url> --source <path>` adds SOURCE audit + entity resolution + dynamic validation (P3.3-4). Without a url, runs the fixture-driven full orchestrator (scope -> recon -> classify -> scan -> judge -> reproduce -> dedup -> report) for a profile.

- `url` — LIVE/HYBRID MODE: target URL to discover/classify/pack-select/pack-run. Omit to use the fixture-based --profile pipeline below.
- `--source` — HYBRID MODE: source tree to audit alongside the url (SOURCE + LIVE correlation and dynamic validation, P3.3-4). Without url: SOURCE-only scan that writes a scan artifact for `validate` (P4.5 WP-03).
- `--artifact` — SOURCE-only scan: artifact output path
- `--captured-requests` — SOURCE-only scan: HAR or JSON list of real requests; overrides inferred request shape
- `--auth-context` — HYBRID MODE only: an authenticated session/account is available for testing, so endpoints with a detected auth guard aren't automatically downgraded to review_only
- `--profile` (default: `quick`)
- `--pipeline-config` (default: `config/pipeline.yaml`)
- `--scope` — Scope/policy YAML. Omit for a localhost/private URL to get a safe auto-scope; public URLs require this. With no URL (fixture --profile mode) defaults to the sample scope.
- `--auth-token` — Bearer token sent as 'Authorization: Bearer ...' by every scanner. Falls back to the BUGBOUNTY_AUTH_TOKEN env var. Redacted in output/evidence.
- `--header` — Extra request header reused by every scanner; repeatable.
- `--tool-timeout` (default: `600.0`) — Per-tool subprocess timeout in seconds for live scanners (default 600).
- `--no-dast` (default: `True`) — Disable nuclei DAST parameter fuzzing (on by default for live URL scans).
- `--full-templates` — With DAST, also run the full nuclei template set (slower, broader) instead of only the fast fuzzing templates.
- `--output, -o` — Results directory. Default: a timestamped folder under ./BugBounty-Results/.
- `--testcases` (default: `testcase/suites/basic.yaml`)
- `--db` (default: `runs/scan.sqlite`)
- `--max-pages` (default: `5`) — LIVE/HYBRID MODE only: max pages for the discovery crawl
- `--auto-profile` — LIVE MODE only: verify classified llm/api candidates via the Capability Probe
- `--pack-target`
- `--pack-target-config`
- `--pack-budget-requests`
- `--nuclei-results` — LIVE MODE only: see `discover --nuclei-results`
- `--dalfox-results` — LIVE MODE only: see `discover --dalfox-results`
- `--trufflehog-results` — LIVE MODE only: see `discover --trufflehog-results`
- `--subfinder-input` (default: `tests/fixtures/tools/subfinder-results.jsonl`)
- `--httpx-input` (default: `tests/fixtures/tools/httpx-results.jsonl`)
- `--katana-input` (default: `tests/fixtures/tools/katana-results.jsonl`)
- `--ffuf-input` (default: `tests/fixtures/tools/ffuf-results.json`)
- `--nuclei-input` (default: `tests/fixtures/tools/nuclei-results.jsonl`)
- `--dalfox-input` (default: `tests/fixtures/tools/dalfox-results.json`)
- `--trufflehog-input` (default: `tests/fixtures/tools/trufflehog-results.jsonl`)
- `--pyrit-input` (default: `tests/fixtures/tools/pyrit-results.json`)
