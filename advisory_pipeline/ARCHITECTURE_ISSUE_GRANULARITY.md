# Architecture Issue: Mixed Granularity in mart_advisory_current

## Status
🔴 **CRITICAL** - Data modeling issue requiring architectural redesign

## Problem Statement

The `mart_advisory_current` table currently mixes two different granularity levels in the same table:

1. **Package-level advisories** (e.g., `example-package:CVE-2024-0001`)
   - From: echo_data, OSV
   - Has: package_name, fixed_version, package-specific metadata

2. **CVE-level advisories** (e.g., `CVE-2024-0001` with NULL package)
   - From: NVD, echo_csv overrides
   - Has: CVSS scores, rejection status, CVE-level metadata
   - NULL package_name

This violates data modeling best practices where each table should represent a single, clear grain/granularity.

## Current Behavior (Incorrect)

```sql
-- mart_advisory_current has BOTH:
CVE-2024-0001, NULL,              pending_upstream, [nvd]  -- CVE-level
CVE-2024-0001, "example-package", fixed,           [osv]  -- Package-level
```

Creates duplicate CVE entries with different granularities, confusing queries and reports.

## Expected Behavior (Correct)

**Option A: Denormalize CVE-level data to package rows**
```sql
-- mart_advisory_current (package-level only):
CVE-2024-0001, "example-package", fixed, cvss_score=7.5, nvd_status=Analyzed
CVE-2024-0001, "another-package", fixed, cvss_score=7.5, nvd_status=Analyzed
```
- CVE-level enrichment (CVSS, rejection status) is duplicated to each package row
- Single granularity: package-level
- NVD/CSV data "left joins" to enrich package rows

**Option B: Separate tables for different grains**
```sql
-- mart_advisory_by_package (package-level):
CVE-2024-0001, "example-package", fixed, ...

-- mart_cve_metadata (CVE-level):
CVE-2024-0001, cvss_score=7.5, nvd_status=Analyzed, ...
```
- Clear separation of concerns
- Applications join as needed

## Impact

**Current Issues:**
1. Confusing duplicate CVE entries in output
2. Inconsistent query patterns (sometimes filter by package, sometimes don't)
3. Difficult to answer simple questions like "how many CVEs are fixed?" (need to handle NULLs)
4. Aggregations become complex (GROUP BY with NULL handling)

**Recommended**: Option A (denormalization) because:
- Simpler query patterns
- Most use cases need both package AND CVE-level info together
- Data volumes are manageable (not billions of rows)
- Aligns with data warehouse best practices (dimensional modeling)

## Proposed Solution

### Phase 1: Modify int_enriched_advisories.sql

1. **Change advisory_keys CTE** to ONLY include package-level keys:
```sql
advisory_keys as (
    select distinct
        package_name || ':' || cve_id as advisory_id,
        cve_id,
        package_name
    from observations
    where cve_id is not null
      and package_name is not null  -- ONLY package-level
)
```

2. **Join NVD signals by cve_id** (not advisory_id):
```sql
from advisory_keys ak
left join csv_overrides csv on ak.advisory_id = csv.advisory_id
left join nvd_signals nvd on ak.cve_id = nvd.cve_id  -- By CVE, not advisory
left join osv_signals osv on ak.advisory_id = osv.advisory_id
```

3. **Add NVD columns** to enriched output:
```sql
-- NVD enrichment (duplicated across packages with same CVE)
nvd.nvd_rejection_status,
nvd.nvd_cvss_score,
nvd.nvd_cvss_vector,
nvd.nvd_description,
```

### Phase 2: Update CSV Override Matching

1. **Allow CSV overrides to match by CVE-only** OR package+CVE:
```sql
csv_overrides as (
    select
        case
            when package_name is not null then package_name || ':' || cve_id
            else cve_id
        end as match_key,
        cve_id,
        override_status,
        override_reason
    from observations
    where source_id = 'echo_csv'
)

-- In enriched CTE:
left join csv_overrides csv on (
    ak.advisory_id = csv.match_key OR ak.cve_id = csv.cve_id
)
```

### Phase 3: Handle Edge Cases

1. **CVEs with no package info** (rare):
   - Could create a synthetic package "unknown" or "unassigned"
   - OR maintain a separate `mart_cve_orphans` table

2. **CSV overrides for CVE-only** (like the demo):
   - Match to ALL packages with that CVE
   - Document that CVE-level overrides apply to all packages

## Testing Requirements

1. Verify no NULL package_name in final mart
2. Verify NVD data (CVSS, rejection) appears on all package rows
3. Verify CSV overrides work for both CVE-level and package-level
4. Verify demo runs successfully with new model
5. Check performance with 40k+ rows

## Migration Path

1. Create new model as `mart_advisory_current_v2`
2. Run in parallel with existing model
3. Validate outputs match (except NULL package rows)
4. Switch applications to new model
5. Deprecate old model

## References

- Current code: [int_enriched_advisories.sql](dbt_project/models/intermediate/int_enriched_advisories.sql)
- Related: [ISSUES_AND_FIXES.md](ISSUES_AND_FIXES.md) Issue #3

## Owner

**Action Required**: Assign to data modeling specialist to design and implement solution.

**Estimated Effort**: 2-3 days
- 1 day: Design and update dbt models
- 1 day: Testing and validation
- 0.5 day: Demo updates and documentation
