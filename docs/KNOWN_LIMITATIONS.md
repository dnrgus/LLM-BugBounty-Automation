# Known limitations (v5.0)

Consolidated list; each item is either a deliberate scope boundary or a measured gap. After v5.0.0, fixes follow the rule in the plan: only real, repeated failures justify changing detection logic (5.0.x patches).

## Dynamic validation
- State-changing methods (POST/PUT/PATCH/DELETE) are planned and recorded (`dry_run`) unless the program policy sets `testing.state_changing_requests: allowed`; even then a body is never synthesized — a captured or user-supplied example body is required.
- Object access comparison is read-only, uses only object ids the tester declared for their own test accounts, and stays `needs_review` with fewer than two usable accounts or without compared key fields.
- Path parameters without a declared value are never filled in; those requests are recorded as `review_required`.
- The endpoint validator's "confirmed" means reachable, not vulnerable.

## Static analysis
- JS/TS dataflow is single-function only; cross-function and cross-file flows are not tracked (WP-05 not implemented). Benchmark impact: 1 holdout false negative (`dataflow_cut`).
- JS/TS sinks reached through a module alias (`const childProcess = require('child_process'); childProcess.exec(x)`) are not recognized.
- Python interprocedural analysis resolves module-level functions only; method calls (`self.repo.find(x)`) are an explicit cut. Benchmark impact: 1 false negative (`dataflow_cut`). No sanitizer recognition.
- Request body inference for JS/TS uses the text between one route registration and the next; imported handlers are not resolved.
- Caps: `max_depth=4`, `max_nodes=500`, `time_budget_s=5` per audit; hitting one is reported in `interprocedural.truncated`.
- Files that make the parser recurse too deeply are skipped per file and listed in `interprocedural.file_errors`.

## Live scanning (`bugbounty scan <url>`)
- Auto-scope is generated only for loopback/private/link-local hosts; a public target requires an explicit `--scope` file (usability never invents authorization).
- nuclei DAST fuzzes parameterized endpoints that discovery surfaced. The built-in crawler is passive (GET/HEAD, no active parameter discovery), so an endpoint like Juice Shop's `/rest/products/search?q=` is only fuzzed if it appears in-page or is provided via `--source`/hybrid mode or a richer crawler (e.g. katana input). Absent that, the DAST run has no parameters to fuzz.
- External-tool findings (nuclei/dalfox) are promoted as `candidate` and filed under `needs_review/`; they are never auto-confirmed (their severity is still preserved).
- Default scan runs the fast nuclei `dast` template set; `--full-templates` also runs the full set (slower). Non-DAST default-template exposures (e.g. Swagger detection) only run with `--full-templates` or `--no-dast`.

## Judge
- The semantic judge is opt-in and wired into `sample-run` only; it can downgrade to `needs_review`, never confirm.

## Benchmark
- The committed dataset contains in-repo fixtures and offline fake targets only — no external real-world vulnerable applications. Numbers (overall 14 GT findings: TP 12 / FP 0 / FN 2) describe this small dataset, not general accuracy. External apps can be added locally via `kind: external` + `path_env`.
- A timed-out benchmark worker thread cannot be killed; it is reported and abandoned.
- `quality-gate` scores static results only; live reproduction rate is measured only against the offline fake targets.

## Platform
- CLI only; no dashboard, SaaS, multi-user or central server (non-goal).
