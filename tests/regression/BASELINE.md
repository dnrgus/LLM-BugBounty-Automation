# v2 stable regression baseline (U0)

Frozen ahead of the v3.0 Universal Bug Bounty Architecture migration.

- **Commit**: `ede8fbd1411567ba8267a99ba321655ee87b9f79`
- **Tag**: `v2-stable-baseline`
- **Tests**: 175 passed, `ruff check .` clean
- **Frozen feature set**: core model/storage, Scope+Program Policy, Fake
  LLM/Agent/RAG targets, OpenAI-compatible + CustomHTTP Target Adapters
  (with Target error taxonomy), Testcase/coverage, Executor/session/trace/
  Approval Gate, Judge Ensemble + benchmark, Reproducer + negative
  controls, Evidence raw/sanitized + redaction, Tool Doctor + Promptfoo/
  Garak/PyRIT adapters, Mutation Engine, Recon (Subfinder/httpx/Katana/
  ffuf), Nuclei/Dalfox/TruffleHog adapters, AI Endpoint Classifier, RAG
  Test Harness, Finding dedup/root-cause clustering, Full Orchestrator
  (`scan --profile`), Attack Budget + graceful stop, Capability Probe,
  `reproduce` + Minimal PoC, Adapter Contract Test suite, GitHub Actions
  CI, Session Strategy (`shared_suite`/`persistent`).

Per the v3.0 design doc's Migration Rules: none of the above is deleted
or replaced wholesale during the v3.0 migration. `tests/regression/`
holds tests that assert this baseline keeps working; U1 adds the golden-
artifact harness that locks down `sample-run`'s actual output shape.
