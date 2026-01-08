# Architecture

## Overview
The pipeline separates ingestion, enrichment, and decisioning. It uses SQLite to persist SCD2 state history and exposes a current-state view for the app.

```
Sources -> Ingestion -> Normalization -> Enrichment -> Decisioning -> Storage -> Publish
   |           |              |              |              |            |
 CSV       data.json       Canonical      OSV/NVD        Rules +       SCD2 table
 live      advisory         keys          adapters       explanations   + current view
 feed
```

## Components
- **Ingestion**: load `data.json` + CSV, validate schema, compute deltas.
- **Normalization**: canonical keys, CVE normalization, exclude non-CVE IDs from NVD.
- **Enrichment adapters**: OSV (package + ecosystem), NVD (CVE id).
- **Decision engine**: deterministic rules with explainability.
- **Storage**: SQLite with SCD2 history and a current-state view.
- **Publish**: materialize a view or JSON output for consumption.

## Data model (high level)
- `advisory_state_history` (SCD2)
  - `advisory_id`, `package`, `cve_id`, `state`, `fixed_version`
  - `explanation`, `reason_code`, `evidence_json`, `decision_rule`
  - `effective_from`, `effective_to`, `is_current`, `run_id`
- `advisory_current` (view)
  - `SELECT * FROM advisory_state_history WHERE is_current=1`

## Efficiency
- Skip processing for final states unless CSV changes or upstream TTL expires.
- Cache upstream responses by `cve_id` (NVD) and `(ecosystem, package)` (OSV).
- Backoff and retry for upstream errors; keep partial progress.

## Observability
- Persist run metadata (counts by state, enriched count, failures).
- Alert on stalled CVEs (no state change for long windows).
- Detect data regressions (schema drift, missing fields).

