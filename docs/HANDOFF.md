# Handoff Checklist

This is the minimal, concrete plan for the next agent to implement the prototype.

## 1) Data ingestion
- Load `data.json` and parse the nested structure: `package -> cve_id -> fixed_version`.
- Load `advisory_not_applicable.csv` into a lookup map keyed by `(package, cve_id)`.

## 2) SQLite schema
- Create `advisory_state_history` (SCD2) and `advisory_current` view.
- Optional: create a `run_metadata` table for per-run stats.

## 3) Enrichment adapters
- OSV: query by `(ecosystem, package)`; parse affected ranges and `fixed` versions.
- NVD: query by `cve_id`; extract `vulnStatus` and references.
- Add caching + TTL to reduce repeated calls.

## 4) Decision engine
- Implement the rule priority in `docs/DECISION_ENGINE.md`.
- Generate explanations from templates.
- Write SCD2 logic: insert when state changes, close prior record.

## 5) Output
- Provide a current-state view for app consumption.
- Optionally dump a JSON view for easy inspection.

