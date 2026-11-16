# ARTEX worker integration (first slice)

Run the local scanner from an ARTEX worker's Bash tool:

```bash
cd /path/to/LLM-BugBounty-Automation
python -m integrations.artex_bridge https://authorized.example --scope config/my-scope.yaml --output /tmp/artex-scan-001
```

For an AI endpoint, add `--target-config config/targets/my-target.yaml --profile llm` to execute the testcase packs against that adapter. Without a target config, AI testcase packs report `skipped_no_target`; URL discovery alone cannot infer an arbitrary chat API's request schema. The scanner still applies the scope policy to adapter requests.

ARTEX already supports user-defined command tools for workers. Generate a tool registration JSON with `python -m integrations.artex_tool_spec --scope /absolute/path/to/scope.yaml` and add `--target-config /absolute/path/to/target.yaml --profile llm` for AI packs. Submit this JSON to ARTEX's authenticated `POST /api/tools/custom` endpoint (or fill the custom-tool editor with the same fields). Paths must be visible inside the ARTEX server environment; when ARTEX runs in Docker, mount the repository, scope file, and Python environment into that container. Each invocation creates a unique output directory under `/tmp`, so concurrent workers do not reuse summaries.

The command prints one `artex-bridge/v1` JSON object. `assets` are original attack-surface items; `artex_assets` contains deduplicated, observed HTTP endpoints in ARTEX's `insert_assets` input shape. JavaScript paths with an unknown method remain only in `assets`. `findings` includes `graph_kind: finding` only for `confirmed` status; `candidate` and `unstable` statuses remain candidates for further worker investigation. Each finding includes a `report_path` for local evidence review. `pack_selection` records policy/budget decisions and `pack_executions` records whether selected tools actually ran; an empty finding list is not evidence that every pack ran. Tool summaries are omitted from this compact contract. A failed scan returns `ok: false` and exits nonzero, so a previous summary cannot be mistaken for a fresh result.

The worker should pass `artex_assets` to `insert_assets`, attach candidate findings as unverified `record_fact` observations, and write confirmed findings with their report path using `report_finding`. The adapter uses the scanner's existing scope and policy gate; a public URL requires an explicit scope file. Use a distinct output directory per work item. ARTEX's worker still performs the graph tool calls; deterministic graph ingestion requires an ARTEX-side change.
