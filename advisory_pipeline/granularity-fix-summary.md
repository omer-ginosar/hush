# Granularity Architecture Fix - Implementation Summary

## Status
✅ **COMPLETED** - Architecture issue resolved and demo polished

## Problem Statement
The `mart_advisory_current` table was mixing two different granularity levels:
1. **Package-level advisories** (e.g., `example-package:CVE-2024-0001`)
2. **CVE-level advisories** (e.g., `CVE-2024-0001` with NULL package)

This violated data modeling best practices and created duplicate CVE entries that confused queries and reports.

## Solution Implemented
Applied a single-granularity approach: denormalize CVE-level data to package rows (single granularity: package-level).

### Changes Made

#### 1. Fixed dbt Model: `int_enriched_advisories.sql`

**advisory_keys CTE** - Only include package-level advisories:
```sql
advisory_keys as (
    select distinct
        package_name || ':' || cve_id as advisory_id,
        cve_id,
        package_name
    from observations
    where cve_id is not null
      and package_name is not null  -- ONLY package-level advisories
)
```

**CSV overrides** - Support both package-specific and CVE-level matches:
```sql
-- Package-specific overrides
csv_overrides_package as (
    select
        package_name || ':' || cve_id as advisory_id,
        override_status, override_reason, csv_updated_at
    from observations
    where source_id = 'echo_csv' and package_name is not null
)

-- CVE-level overrides (apply to ALL packages with that CVE)
csv_overrides_cve as (
    select cve_id, override_status, override_reason, csv_updated_at
    from observations
    where source_id = 'echo_csv' and package_name is null
)
```

**Join logic** - Denormalize NVD data by cve_id, prioritize package-specific CSV overrides:
```sql
from advisory_keys ak
left join csv_overrides_package csv_pkg on ak.advisory_id = csv_pkg.advisory_id
left join csv_overrides_cve csv_cve on ak.cve_id = csv_cve.cve_id
left join nvd_signals nvd on ak.cve_id = nvd.cve_id  -- Denormalize by CVE
```

**Other CTEs** - Removed NULL package handling from osv_signals, echo_signals, and source_contributions.

#### 2. Fixed Staging Model: `stg_echo_advisories.sql`
- Removed `fix_available` and `fixed_version` columns (don't exist in raw_echo_advisories table)
- These fields only exist in OSV observations

#### 3. Fixed Intermediate Model: `int_source_observations.sql`
- Changed echo_advisories CTE to use `null::boolean as fix_available` instead of reading from staging

#### 4. Updated Demo: `demo.py`
- Changed CSV override scenario from CVE-2024-0002 (NVD-only) to CVE-2024-0003 (db-handler package)
- Updated tracked CVEs from 4 to 3 (removed CVE-2024-0002 which has no package context)
- Updated demo narrative to reflect the fix
- Added "Granularity Fix Applied" section to summary

#### 5. Updated Documentation: `demo.md`
- Added section explaining the granularity fix
- Updated example output to show no more duplicate entries
- Documented benefits of single granularity approach

## Results

### Before the Fix
- **Total advisories**: 40,195
- **Issue**: Duplicate CVE-only entries (NULL package_name)
- **Example**: CVE-2024-0001 appeared twice:
  - `CVE-2024-0001 (example-package)` - package-level
  - `CVE-2024-0001 (NULL)` - CVE-only

### After the Fix
- **Total advisories**: 40,192 (3 fewer)
- **Resolution**: All advisories are package-level
- **Example**: CVE-2024-0001 appears once:
  - `CVE-2024-0001 (example-package)` - with NVD data denormalized

### Demo Output Comparison

**Before:**
```
📊 CVE Journey Tracker - After Run 2

  ✅ CVE-2024-0001 (example-package)
     State: fixed (confidence: high)

  ↳ ⏳ CVE-2024-0001 (NULL)  ← Duplicate CVE-only entry
     State: pending_upstream (confidence: medium)
```

**After:**
```
📊 CVE Journey Tracker - After Run 2

  ✅ CVE-2024-0001 (example-package)
     State: fixed (confidence: high)
     (NVD enrichment denormalized - CVSS, rejection status included)
```

## Benefits

1. **Single Granularity** - Every advisory is package-level (package:CVE)
2. **No Duplicates** - No more confusing NULL package entries
3. **Simpler Queries** - No need to handle NULL package_name in GROUP BY
4. **Clear Semantics** - Each row represents a package affected by a CVE
5. **Flexible Overrides** - CSV can override specific packages OR all packages via CVE-level match
6. **NVD Enrichment** - CVSS scores and rejection status denormalized across all packages

## Edge Cases Handled

### CVEs Without Package Context
- **Scenario**: CVE exists in NVD but no package data from OSV/Echo
- **Handling**: Excluded from package-level mart (per architecture design)
- **Future**: Could be tracked in separate `mart_cve_orphans` table for monitoring

### CSV Override Granularity
- **Package-specific**: Matches exact package:CVE (e.g., `db-handler:CVE-2024-0003`)
- **CVE-level**: Matches all packages with that CVE (e.g., `CVE-2024-0003` with NULL package)
- **Priority**: Package-specific overrides take precedence over CVE-level

## Testing

Demo successfully runs 3 pipeline iterations showing:
- ✅ Package-level granularity maintained
- ✅ No duplicate entries
- ✅ CSV override works (CVE-2024-0003: fixed → not_applicable)
- ✅ State transitions tracked (CVE-2024-0004: under_investigation → fixed)
- ✅ NVD enrichment visible on package rows
- ✅ SCD2 history captures state changes

## Files Modified

1. `dbt_project/models/intermediate/int_enriched_advisories.sql` - Core granularity fix
2. `dbt_project/models/staging/stg_echo_advisories.sql` - Removed non-existent columns
3. `dbt_project/models/intermediate/int_source_observations.sql` - Fixed echo CTE
4. `demo.py` - Updated scenario and narrative
5. `demo.md` - Updated documentation

## Next Steps (Optional)

1. **Create `mart_cve_orphans` table** - Track CVEs with no package context
2. **Add data quality checks** - Alert on unexpected NULL packages
3. **Performance testing** - Validate denormalization doesn't impact query performance at scale

## Conclusion

The granularity fix successfully resolves the architectural issue by:
- Maintaining single package-level granularity
- Denormalizing CVE metadata across packages
- Supporting both package-specific and CVE-level CSV overrides
- Providing clean, unambiguous data for downstream consumers

The demo now clearly shows how the system handles realistic scenarios without confusing duplicate entries.
