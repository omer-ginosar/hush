# Phase 11: Bug Fixes - Implementation Documentation

## Overview

This document describes the implementation of 4 critical bug fixes identified during Phase 8 demo testing. These bugs prevented proper state tracking, audit trails, and analyst workflow functionality.

## Architecture Decision: SCD2 Implementation

The original implementation plan called for using dbt snapshots instead of the Python `scd2_manager.py`. This decision was made because:

1. **Declarative over imperative**: dbt snapshots are configuration-driven, making change detection logic explicit
2. **Standard pattern**: dbt snapshots are the industry-standard approach for SCD Type 2
3. **Idempotency**: Snapshots can be re-run safely without side effects
4. **Simpler codebase**: Eliminates redundant Python code

## Bug Fixes

### Bug 1: SCD2 History Table Not Populated

**Impact**: No historical state tracking, no audit trail, state_changes always = 0

**Implementation**:

1. Created dbt snapshot configuration:
   ```sql
   -- snapshots/advisory_state_snapshot.sql
   {% snapshot advisory_state_snapshot %}
   {{
       config(
         target_schema='main',
         unique_key='advisory_id',
         strategy='check',
         check_cols=['state', 'fixed_version', 'confidence', 'reason_code', 'explanation']
       )
   }}
   select * from {{ ref('mart_advisory_current') }}
   {% endsnapshot %}
   ```

2. Created mapping model from snapshot to advisory_state_history schema:
   - `mart_advisory_state_history.sql` transforms dbt snapshot columns to our table schema
   - Maps `dbt_valid_from` → `effective_from`, `dbt_valid_to` → `effective_to`
   - Sets `is_current = (dbt_valid_to is null)`

3. Updated pipeline orchestrator:
   - Added `_run_dbt_snapshots()` method to run `dbt snapshot` command
   - Executes after `dbt run` (Stage 3b)
   - Properly manages database connection lifecycle

**Files**:
- `dbt_project/snapshots/advisory_state_snapshot.sql` (NEW)
- `dbt_project/models/marts/mart_advisory_state_history.sql` (NEW)
- `dbt_project/dbt_project.yml` (added snapshot config)
- `advisory_pipeline/run_pipeline.py` (added snapshot execution)

---

### Bug 2: State Change Detection Broken

**Impact**: Metrics always showed 0 state changes, even when CVEs visibly changed

**Root Cause**: Tried to query empty advisory_state_history table (Bug 1)

**Implementation**:

Updated `_finalize_metrics()` to:
1. Check if snapshot table exists
2. Count advisories with historical versions (not just current)
3. Only advisories with `dbt_valid_to IS NOT NULL` on previous version count as changes
4. Graceful fallback to 0 if snapshot doesn't exist yet

**Query Logic**:
```sql
WITH current_run_records AS (
    SELECT advisory_id
    FROM main.advisory_state_snapshot
    WHERE dbt_valid_from >= (current run start time)
),
has_history AS (
    SELECT DISTINCT curr.advisory_id
    FROM current_run_records curr
    WHERE EXISTS (
        SELECT 1
        FROM main.advisory_state_snapshot prev
        WHERE prev.advisory_id = curr.advisory_id
          AND prev.dbt_valid_to IS NOT NULL  -- Has a closed version = changed
    )
)
SELECT count(*) FROM has_history
```

**Files**:
- `advisory_pipeline/run_pipeline.py` (`_finalize_metrics()` method)

---

### Bug 3: CSV Override Not Working for NVD-Only CVEs

**Impact**: ~38k CVEs from NVD couldn't be overridden by analysts

**Root Cause**: `stg_echo_csv.sql` filtered out rows where `package_name is null`

**Implementation**:

Changed staging model to allow NULL package_name:
```sql
-- Before
where cve_id is not null
  and package_name is not null  -- ❌ Blocked NVD overrides

-- After
where cve_id is not null
  and trim(cve_id) != ''  -- ✅ Allows package_name = NULL
```

**Why This Works**:

The `int_enriched_advisories.sql` advisory_id logic already handles this correctly:
```sql
case
    when package_name is not null then package_name || ':' || cve_id
    else cve_id  -- CVE-only advisory (matches NVD records)
end as advisory_id
```

When CSV has NULL package_name:
- advisory_id = `CVE-2024-0002`
- Matches NVD record advisory_id = `CVE-2024-0002`
- Override applied ✅

**Files**:
- `dbt_project/models/staging/stg_echo_csv.sql`

---

### Bug 4: Duplicate CVE Entries

**Impact**: Each CVE appeared multiple times (once per package + once from NVD), confusing users

**Design Decision**: Package-Level Base + CVE-Level View (Option 1)

**Rationale**:
| Consideration | Package-Level Base | CVE-Level Only |
|---------------|-------------------|----------------|
| Security analysis | ✅ Can see per-package status | ❌ Loses granularity |
| Reporting | Use dedupe view | ✅ Native |
| Analyst workflow | ✅ Full detail | ❌ Hidden info |
| Extensibility | ✅ Easy to add features | ❌ Hard to retrofit |
| Storage | Minimal overhead | Smaller |

**Implementation**:

Created deduplicated view `mart_advisory_current_by_cve`:

1. **State Priority** (worst state wins):
   ```
   1. under_investigation  (highest priority - needs action)
   2. pending_upstream
   3. wont_fix
   4. not_applicable
   5. fixed                (lowest priority)
   ```

2. **Aggregation Logic**:
   - Rank all package-level entries per CVE by state priority
   - Select entry with worst state as "primary"
   - Collect list of all affected packages
   - Add multi-package context to explanation

3. **Output Schema**:
   ```sql
   advisory_id VARCHAR          -- CVE (unique)
   cve_id VARCHAR
   affected_packages LIST       -- All packages affected
   package_count INTEGER
   primary_package VARCHAR      -- Package used for state
   state VARCHAR                -- From primary package
   explanation_with_context     -- Includes multi-package note
   ```

**Usage**:
```sql
-- Analyst triage: see all package-level detail
SELECT * FROM main_marts.mart_advisory_current
WHERE cve_id = 'CVE-2024-0001';

-- Dashboard/reporting: one row per CVE
SELECT * FROM main_marts.mart_advisory_current_by_cve
WHERE cve_id = 'CVE-2024-0001';
```

**Files**:
- `dbt_project/models/marts/mart_advisory_current_by_cve.sql` (NEW)
- `dbt_project/models/marts/marts.yml` (updated docs)

---

## Testing

### Validation Steps

1. **Bug 1 - SCD2 History**:
   ```bash
   # Run pipeline twice
   python run_pipeline.py
   python run_pipeline.py

   # Verify snapshot exists and has records
   duckdb advisory_pipeline.duckdb "SELECT COUNT(*) FROM main.advisory_state_snapshot"
   ```

2. **Bug 2 - State Changes**:
   ```bash
   # Modify data between runs
   echo "CVE-2024-0004,example-package,not_applicable,Test" >> data/analysts_overrides.csv
   python run_pipeline.py

   # Check metrics show state_changes > 0
   ```

3. **Bug 3 - CSV Overrides**:
   ```csv
   # Add CVE-only override (no package)
   CVE-2024-0002,,not_applicable,Out of scope

   # Verify it applies to NVD record
   duckdb advisory_pipeline.duckdb "
   SELECT state FROM main_marts.mart_advisory_current
   WHERE cve_id = 'CVE-2024-0002'
   "
   # Expected: not_applicable
   ```

4. **Bug 4 - Deduplication**:
   ```sql
   -- Verify package-level has duplicates
   SELECT cve_id, count(*) as cnt
   FROM main_marts.mart_advisory_current
   GROUP BY cve_id
   HAVING count(*) > 1
   LIMIT 5;

   -- Verify CVE-level is unique
   SELECT cve_id, count(*) as cnt
   FROM main_marts.mart_advisory_current_by_cve
   GROUP BY cve_id
   HAVING count(*) > 1;
   -- Expected: 0 rows
   ```

---

## Documentation Updates

### marts.yml

Added clear descriptions distinguishing the two views:

- `mart_advisory_current`: "PACKAGE-LEVEL GRANULARITY... For detailed triage"
- `mart_advisory_current_by_cve`: "ONE ROW PER CVE... For reporting and dashboards"

### Inline Comments

All SQL models now include:
- Purpose and use case comments
- Advisory_id generation logic explanation
- Deduplication strategy rationale

---

## Known Limitations

1. **State change detection**: Counts changes since last run only, not cumulative
2. **Deduplication tie-breaking**: If two packages have same state, picks arbitrary primary
3. **Snapshot retention**: No automatic cleanup of old snapshot records (not needed for prototype)

---

## Future Enhancements (Out of Scope)

1. Add dbt tests for snapshot validity
2. Implement snapshot retention policy
3. Add deduplication statistics to observability metrics
4. Consider materialized view for performance at scale

---

## Files Changed

### New Files (3)
- `dbt_project/snapshots/advisory_state_snapshot.sql`
- `dbt_project/models/marts/mart_advisory_state_history.sql`
- `dbt_project/models/marts/mart_advisory_current_by_cve.sql`

### Modified Files (4)
- `advisory_pipeline/run_pipeline.py`
- `dbt_project/dbt_project.yml`
- `dbt_project/models/staging/stg_echo_csv.sql`
- `dbt_project/models/marts/marts.yml`

**Total**: 7 files, ~280 lines added

---

## Breaking Changes

None. All changes are:
- Additive (new views, new snapshots)
- Bug fixes (incorrect behavior → correct behavior)
- Non-breaking to existing APIs

---

## Acceptance Criteria Met

- ✅ `SELECT COUNT(*) FROM advisory_state_snapshot` returns > 0 after demo run
- ✅ Demo shows `state_changes > 0` when CVEs transition
- ✅ CVE-2024-0002 shows `not_applicable` after CSV override with NULL package
- ✅ Each CVE appears exactly once in `mart_advisory_current_by_cve`
- ✅ Package-level detail preserved in `mart_advisory_current`
- ✅ Demo journey tracker shows single entry per CVE (using by_cve view)
- ✅ All dbt models compile successfully
- ✅ Documentation clearly explains when to use each view
