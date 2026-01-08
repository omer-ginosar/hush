# Runbook (Prototype)

This runbook describes the expected operator steps once the prototype is implemented. It is intentionally lightweight and may be adjusted as the implementation solidifies.

## Prerequisites
- Python 3.9+
- Internet access (OSV + NVD APIs)
- Optional: NVD API key (recommended for higher rate limits)

Suggested environment variables:
- `NVD_API_KEY` (optional)

## Data placement
- Place `data.json` (Echo advisory dataset) in the repo root.
- Keep `advisory_not_applicable.csv` in the repo root.

## Proposed CLI (to be implemented)
```
python prototype.py \
  --data data.json \
  --csv advisory_not_applicable.csv \
  --db advisory.db \
  --run-id 20250108T120000Z
```

## Expected outputs
- `advisory.db` with:
  - `advisory_state_history` (SCD2 table)
  - `advisory_current` (view)
  - `run_metadata` (per-run stats)
- Optional JSON export of `advisory_current` for quick inspection.

## Basic validation queries
```
sqlite3 advisory.db "select state, count(*) from advisory_current group by state;"
sqlite3 advisory.db "select * from advisory_current where state='pending_upstream' limit 10;"
```

## Troubleshooting
- If OSV returns empty results:
  - Verify ecosystem mapping (likely `Debian`).
  - Test with a known package + CVE from `data.json`.
- If NVD requests are slow or throttled:
  - Provide `NVD_API_KEY`.
  - Add caching and TTL to reduce repeated requests.

