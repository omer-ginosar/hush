# Root Cause Analysis and Fixes

## Issue #1: Fixed version from data.json being ignored

### Root Cause
The `echo_data` adapter correctly captures `fixed_version` and `fix_available` from data.json, but the dbt models discard these signals:

1. **Staging Model** ([stg_echo_advisories.sql:19-22](dbt_project/models/staging/stg_echo_advisories.sql#L19-L22)) - Doesn't include `fixed_version` or `fix_available` columns
2. **Source Observations** ([int_source_observations.sql:17-18](dbt_project/models/intermediate/int_source_observations.sql#L17-L18)) - Sets both to NULL
3. **Enrichment Model** ([int_enriched_advisories.sql:110](dbt_project/models/intermediate/int_enriched_advisories.sql#L110)) - Only considers OSV signals for `fix_available`

This means Echo's own advisory data (40k+ CVEs with fixed versions) is completely ignored in favor of OSV, which has much less coverage.

### Fix

**1. Update stg_echo_advisories.sql:**
```sql
validated as (
    select
        observation_id,
        case
            when cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$' then cve_id
            else null
        end as cve_id,
        nullif(trim(package_name), '') as package_name,
        observed_at,
        raw_payload,
        lower(trim(status)) as status,
        fix_available,          -- ADD THIS
        fixed_version,          -- ADD THIS
        cvss_score,
        notes,
        run_id,
        case when cve_id !~ '^CVE-[0-9]{4}-[0-9]{4,}$' then true else false end as has_invalid_cve
    from source
    where package_name is not null
      and trim(package_name) != ''
)
```

**2. Update int_source_observations.sql:**
```sql
echo_advisories as (
    select
        observation_id,
        'echo_data' as source_id,
        cve_id,
        package_name,
        observed_at,
        null::timestamp as source_updated_at,
        status,
        null::varchar as override_status,
        null::varchar as override_reason,
        null::varchar as rejection_status,
        cvss_score,
        null::varchar as cvss_vector,
        fix_available,          -- CHANGE FROM null::boolean
        fixed_version,          -- CHANGE FROM null::varchar
        notes,
        run_id
    from {{ ref('stg_echo_advisories') }}
    where not has_invalid_cve
),
```

**3. Update int_enriched_advisories.sql to add echo_data signals:**

Add after `nvd_signals` CTE (around line 38):
```sql
-- Aggregate echo_data signals (Echo's own advisory data)
echo_signals as (
    select
        case
            when package_name is not null then package_name || ':' || cve_id
            else cve_id
        end as advisory_id,
        max(fix_available) as echo_fix_available,
        max(fixed_version) as echo_fixed_version
    from observations
    where source_id = 'echo_data'
      and cve_id is not null
    group by case
        when package_name is not null then package_name || ':' || cve_id
        else cve_id
    end
),
```

Update the join in `enriched` CTE (around line 127):
```sql
    from advisory_keys ak
    left join csv_overrides csv on ak.advisory_id = csv.advisory_id
    left join nvd_signals nvd on ak.cve_id = nvd.cve_id
    left join osv_signals osv on ak.advisory_id = osv.advisory_id
    left join echo_signals echo on ak.advisory_id = echo.advisory_id  -- ADD THIS
    left join source_contributions sc on ak.advisory_id = sc.advisory_id
```

Update conflict resolution logic (around line 110):
```sql
        -- Resolved signals (conflict resolution)
        -- Fix available: TRUE if ANY source says true (echo_data OR osv)
        coalesce(
            echo.echo_fix_available,  -- Prefer Echo's own data
            osv.osv_fix_available,
            false
        ) as fix_available,

        -- Fixed version: prefer echo_data (most authoritative for Echo packages), then OSV
        coalesce(
            echo.echo_fixed_version,
            osv.osv_fixed_version
        ) as fixed_version,
```

---

## Issue #2: CVE-2024-0002 shows as not_applicable in Run 1

### Root Cause
The demo's `create_csv_override(include_override=False)` function doesn't remove the demo CVE from the CSV file. The CSV file at `../advisory_not_applicable.csv` persists between demo runs with:
```
CVE-2024-0002,,not_applicable,,demo_override
```

So Run 1 picks up this override, making it appear as `not_applicable` from the start.

### Fix

Update [demo.py:create_csv_override()](demo.py#L183):
```python
def create_csv_override(include_override: bool = False):
    """
    Create CSV override file.

    Args:
        include_override: If True, adds CVE-2024-0002 as not_applicable
    """
    # Write to the path configured in config.yaml
    csv_path = Path("../advisory_not_applicable.csv")

    # Always read existing overrides (exclude demo CVE)
    existing_overrides = []
    if csv_path.exists():
        with open(csv_path, "r", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Skip our demo CVE - we'll conditionally add it back
                if row.get("cve_id") != "CVE-2024-0002":
                    existing_overrides.append(row)

    # Write back existing overrides
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "cve_id", "package", "status", "fixed_version", "internal_status"
        ])
        writer.writeheader()

        # Write existing overrides first
        for row in existing_overrides:
            writer.writerow(row)

        # Add demo override only if requested
        if include_override:
            writer.writerow({
                "cve_id": "CVE-2024-0002",
                "package": "",  # Empty to match NVD-only entry
                "status": "not_applicable",
                "fixed_version": "",
                "internal_status": "demo_override"
            })
```

---

## Issue #3: NVD appearing as a package name

### Root Cause
This is **cosmetic only** - not a modeling issue. The actual data model is correct:
- NVD adapter sets `package_name=None` (line 136 in [nvd_adapter.py](ingestion/nvd_adapter.py#L136))
- Database stores NULL for package_name
- Demo display code shows "NVD" or "NVD-only" as a label for NULL values

### Fix
No fix needed in data model. If you want clearer display labels, update demo.py:
- Line 353: `pkg_display = pkg if pkg else "NVD-only"` → Could be "No Package" or "(CVE-level)"
- Line 407: `pkg_display = (pkg if pkg else "NVD")[:16]` → Could be "N/A" or "-"

This is purely presentation - the underlying architecture correctly distinguishes:
- Package-specific advisories (from echo_data, OSV)
- CVE-level advisories (from NVD, which doesn't track packages)

---

## Issue #4: state_changes always shows 0

### Root Cause
The state change detection logic in [run_pipeline.py:527-548](run_pipeline.py#L527-L548) has a timing issue:

```sql
WHERE dbt_valid_from >= (
    SELECT max(started_at)
    FROM pipeline_runs
    WHERE run_id = ?
)
```

This looks for snapshot records created after the current run started. But **dbt snapshots run at the END of the pipeline**, so:
- Run 1: Snapshot at time T1 - no previous records exist, 0 changes
- Run 2: Snapshot at time T2 - but query looks for records >= T2, finds only new insertions, not updates

The query should compare snapshots FROM the current run AGAINST snapshots from previous runs, not based on timestamps.

### Fix

Replace the state_changes calculation logic in `_finalize_metrics()`:

```python
if snapshot_exists > 0:
    # Count state transitions: advisory_ids that have multiple versions in snapshot
    # (one expired with dbt_valid_to != NULL, one current with dbt_valid_to = NULL)
    state_changes = conn.execute("""
        SELECT COUNT(DISTINCT advisory_id)
        FROM main.advisory_state_snapshot
        WHERE dbt_valid_to IS NOT NULL  -- Has been superseded
          AND dbt_updated_at >= (
              -- Only count changes from this run
              SELECT max(started_at)
              FROM pipeline_runs
              WHERE run_id = ?
          )
    """, [metrics.run_id]).fetchone()[0]

    metrics.state_changes = state_changes
```

This counts advisory_ids that have an expired record (indicating a state transition) that was updated during this run.

**Alternative (more accurate):**
```python
state_changes = conn.execute("""
    WITH snapshot_counts AS (
        SELECT
            advisory_id,
            COUNT(*) as version_count
        FROM main.advisory_state_snapshot
        GROUP BY advisory_id
    )
    SELECT COUNT(*)
    FROM snapshot_counts
    WHERE version_count > 1  -- Has multiple versions = state changed
      AND advisory_id IN (
          -- Only include advisories touched in this run
          SELECT DISTINCT advisory_id
          FROM main.advisory_state_snapshot
          WHERE dbt_updated_at >= (
              SELECT max(started_at)
              FROM pipeline_runs
              WHERE run_id = ?
          )
      )
""", [metrics.run_id]).fetchone()[0]
```

This explicitly counts advisories with multiple snapshot versions that were updated in the current run.

---

## Summary

| Issue | Type | Severity | Fix Location |
|-------|------|----------|--------------|
| #1: Echo fixed_version ignored | **Data Loss** | **CRITICAL** | 3 dbt models |
| #2: CSV override in Run 1 | Demo Bug | Medium | demo.py |
| #3: NVD as package | Cosmetic | Low | demo.py (optional) |
| #4: state_changes = 0 | Metric Bug | Medium | run_pipeline.py |

**Priority:**
1. Fix Issue #1 first - this is losing 40k+ fixed version signals from Echo's own data
2. Fix Issue #4 - metrics are important for observability
3. Fix Issue #2 - demo needs to show proper progression
4. Issue #3 is cosmetic only - optional

All fixes are root-level architectural corrections, not cosmetic patches.
