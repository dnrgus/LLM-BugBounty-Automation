# Frozen schemas (v5.0)

Source of truth: `core/contract.py` (`SCHEMA_VERSIONS`, `FINDING_STATES`, `REQUIRED_REPORT_FIELDS`, `EXIT_CODES`). Any change is a breaking change.

| schema | version | where | checked by |
|---|---|---|---|
| scope/policy config | 1 | `config/scope*.yaml` (`schema_version` optional, absent = 1) | `PolicyEngine.__init__` |
| scan artifact | 1 | `scan --source` output | `validation.workflow.load_scan_artifact` |
| evidence manifest | 1 | `reporting.integrity.RunManifest.to_dict()` | `schema_version` key |
| validation report | 1 | `report` per-finding JSON | `REQUIRED_REPORT_FIELDS` test |
| benchmark dataset | 1 | `benchmarks/datasets/manifest.yaml` | `benchmarks.dataset.load_dataset` |

## Scope/policy keys that gate execution

- `scope.domains`, `scope.allow_subdomains`, `scope.url_patterns`, `scope.deny_domains`, `scope.deny_url_patterns`
- `testing.automated_scanning` (must be true for any request), per-category flags (`prompt_injection`, `tool_abuse`, ...)
- `testing.state_changing_requests`: `dry_run` (default) | `review_required` | `allowed`
- `testing.destructive_actions`: required (with `allowed`) before DELETE is sent; `blocked_actions: [delete]` blocks it outright
- `limits.max_requests_per_run`, `approval_required`, `blocked_actions`

## Evidence layout

```
evidence/
  raw/<run_id>_<name>.json          # original payload, never overwritten
  sanitized/<run_id>_<name>.json    # redacted copy (bearer tokens, API keys, cookies, canaries, emails, AWS keys, private keys)
  sanitized/<run_id>_<name>.redaction.log     # what was redacted (pattern name + count, never the values)
```

Every file is recorded in SQLite `evidence` (`sha256` of the sanitized file, `raw_sha256` of the raw file). `report` and `reporting.integrity.build_run_manifest` re-hash both; a mismatch is `tamper_detected: true` and the report does not quote that evidence.

## Validation report (per finding, JSON)

Required fields: `schema_version`, `finding_id`, `title`, `status`, `severity`, `confidence`, `validator_type`, `reason`, `evidence` (`id`, `path`, `sha256`, `tamper_detected`), `reproductions` (`attempts`, `successes`, `status`), `reproduction_steps`, `limitations`.

## Reproduction record

`reproduce` output always includes `environment`: `python`, `platform`, `package_version`, `contract_version`, and the conditions used (target kind/config hash, testcase suite hash, scope hash, validator type, attempts). The object-access path also stores it in the reproduction evidence file.
