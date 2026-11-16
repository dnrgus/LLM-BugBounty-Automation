# ARTEX worker integration (first slice)

Run the local scanner from an ARTEX worker's Bash tool:

```bash
cd /path/to/LLM-BugBounty-Automation
python -m integrations.artex_bridge https://authorized.example --scope config/my-scope.yaml --output /tmp/artex-scan-001
```

The command prints one `artex-bridge/v1` JSON object. `assets` are observed attack-surface items. `findings` includes `graph_kind: finding` only for `confirmed` status; `candidate` and `unstable` statuses remain candidates for further worker investigation. Each finding includes a `report_path` for local evidence review. A failed scan returns `ok: false` and exits nonzero, so a previous summary cannot be mistaken for a fresh result.

The worker should write assets as graph assets, attach candidate findings as unverified observations, and write confirmed findings with their report path. The adapter uses the scanner's existing scope and policy gate; a public URL requires an explicit scope file. Use a distinct output directory per work item. This is a worker tool contract; automatic ARTEX graph ingestion still requires a change in the ARTEX repository.
