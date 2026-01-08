# Decision Engine

The decision engine produces a single, explainable state for each advisory `(package, cve_id)` and persists state history as SCD2.

## Inputs
- `data.json` (Echo base advisory view).
- `advisory_not_applicable.csv` (authoritative live feed).
- Upstream signals (OSV + NVD).

## Normalization
- Canonical key: `(package, cve_id)` with `cve_id` uppercased.
- Non-CVE IDs (e.g., `TEMP-*`) are excluded from NVD lookups.
- Package names are kept as-is; ecosystem mapping happens in the OSV adapter.

## Evidence model (normalized)
- `source`: `osv` or `nvd`
- `source_id`: OSV vuln ID or NVD CVE id
- `captured_at`: timestamp
- `url`: source URL
- `confidence`: heuristic score (optional)
- `raw_payload`: JSON (stored for traceability)
- `normalized`: JSON (uniform fields like `fixed_version`, `status`, `references`)

## Rule priority (deterministic)
1. **CSV override**  
   If `(package, cve_id)` exists in CSV, set state to `not_applicable`.  
   Explanation includes `internal_status` and CSV timestamp.
2. **Upstream rejected/withdrawn**  
   If NVD `vulnStatus=Rejected` or OSV `withdrawn`, set state to `not_applicable`.  
   Explanation cites source and status.
3. **Fix found (OSV)**  
   If OSV contains a `fixed` version for the package, set state to `fixed` with `fixed_version`.  
   Explanation cites OSV range and fixed version.
4. **Fallback**  
   Otherwise set `pending_upstream`.

## State transitions
- `unknown` -> `pending_upstream` -> `fixed` / `not_applicable`
- CSV and upstream evidence can move an advisory from any non-final state to a final state.
- Final states only re-open if upstream evidence or CSV explicitly changes.

## Explanation templates
- `not_applicable` (CSV):  
  "Marked not applicable via live feed (internal_status={value}) on {date}."
- `not_applicable` (upstream):  
  "Marked not applicable based on {source} status {status} on {date}."
- `fixed`:  
  "Fix identified from OSV for {package} at version {fixed_version} (range {range})."
- `pending_upstream`:  
  "No fix found in upstream sources; awaiting further updates."

## SCD2 persistence
- Insert a new row only when the computed state differs from the current state.
- Close previous row with `effective_to` and `is_current=0`.
- New row gets `effective_from` and `is_current=1`.
- Populate `state_type` as `final` for `fixed` and `not_applicable` (and `wont_fix` if introduced); otherwise `non_final`.

## Open question
- CSV `fixed_version` when `status=not_applicable` is retained as a TODO (see `docs/OPEN_QUESTIONS.md`).
