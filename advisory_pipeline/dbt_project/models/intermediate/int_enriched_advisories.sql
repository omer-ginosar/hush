-- Enriched advisories with aggregated signals from all sources
-- Implements conflict resolution logic

with observations as (
    select * from {{ ref('int_source_observations') }}
),

-- Get unique advisory identifiers (package:CVE combinations)
-- ARCHITECTURE FIX: Only include package-level advisories
-- CVE-only entries (NULL package_name) are excluded to maintain single granularity
-- NVD data is denormalized across all package rows via cve_id join
advisory_keys as (
    select distinct
        package_name || ':' || cve_id as advisory_id,
        cve_id,
        package_name
    from observations
    where cve_id is not null
      and package_name is not null  -- ONLY package-level advisories
),

-- Aggregate CSV overrides (highest priority)
-- ARCHITECTURE FIX: Support both package-specific and CVE-level overrides
-- CVE-level overrides (NULL package) will be joined to ALL packages via cve_id
csv_overrides_package as (
    select
        package_name || ':' || cve_id as advisory_id,
        override_status,
        override_reason,
        source_updated_at as csv_updated_at
    from observations
    where source_id = 'echo_csv'
      and override_status is not null
      and package_name is not null
),

csv_overrides_cve as (
    select
        cve_id,
        override_status,
        override_reason,
        source_updated_at as csv_updated_at
    from observations
    where source_id = 'echo_csv'
      and override_status is not null
      and package_name is null
),

-- Aggregate NVD signals
nvd_signals as (
    select
        cve_id,
        max(rejection_status) as nvd_rejection_status,
        max(cvss_score) as nvd_cvss_score,
        max(cvss_vector) as nvd_cvss_vector,
        max(notes) as nvd_description
    from observations
    where source_id = 'nvd'
    group by cve_id
),

-- Aggregate OSV signals (package-level only)
osv_signals as (
    select
        package_name || ':' || cve_id as advisory_id,
        max(fix_available) as osv_fix_available,
        max(fixed_version) as osv_fixed_version,
        max(notes) as osv_summary
    from observations
    where source_id = 'osv'
      and package_name is not null  -- OSV provides package-level data
    group by package_name || ':' || cve_id
),

-- Aggregate echo_data signals (Echo's own advisory data with fixed versions)
echo_signals as (
    select
        package_name || ':' || cve_id as advisory_id,
        max(fix_available) as echo_fix_available,
        max(fixed_version) as echo_fixed_version
    from observations
    where source_id = 'echo_data'
      and cve_id is not null
      and package_name is not null
    group by package_name || ':' || cve_id
),

-- List contributing sources per advisory
source_contributions as (
    select
        package_name || ':' || cve_id as advisory_id,
        list(distinct source_id) as contributing_sources
    from observations
    where cve_id is not null
      and package_name is not null  -- Package-level only
    group by package_name || ':' || cve_id
),

-- Combine all signals
enriched as (
    select
        ak.advisory_id,
        ak.cve_id,
        ak.package_name,

        -- CSV override signals (package-specific takes precedence over CVE-level)
        coalesce(csv_pkg.override_status, csv_cve.override_status) as override_status,
        coalesce(csv_pkg.override_reason, csv_cve.override_reason) as override_reason,
        coalesce(csv_pkg.csv_updated_at, csv_cve.csv_updated_at) as csv_updated_at,

        -- NVD signals (denormalized across all packages with same CVE)
        nvd.nvd_rejection_status,
        nvd.nvd_cvss_score,
        nvd.nvd_cvss_vector,
        nvd.nvd_description,

        -- OSV signals
        osv.osv_fix_available,
        osv.osv_fixed_version,
        osv.osv_summary,

        -- Echo signals
        echo.echo_fix_available,
        echo.echo_fixed_version,

        -- Resolved signals (conflict resolution)
        -- Fix available: TRUE if any source says true (prioritize echo, then osv)
        coalesce(echo.echo_fix_available, osv.osv_fix_available, false) as fix_available,

        -- Fixed version: prefer echo_data (most authoritative for Echo packages), then OSV
        coalesce(echo.echo_fixed_version, osv.osv_fixed_version) as fixed_version,

        -- CVSS: prefer NVD (authoritative, denormalized)
        nvd.nvd_cvss_score as cvss_score,

        -- Is rejected: only from NVD (denormalized)
        nvd.nvd_rejection_status = 'rejected' as is_rejected,

        -- Contributing sources
        sc.contributing_sources,

        -- Calculate staleness (simplified - would use last_checked in production)
        0.0 as staleness_score

    from advisory_keys ak
    -- Join CSV overrides: package-specific first, then CVE-level
    left join csv_overrides_package csv_pkg on ak.advisory_id = csv_pkg.advisory_id
    left join csv_overrides_cve csv_cve on ak.cve_id = csv_cve.cve_id
    -- Join NVD by cve_id to denormalize CVE-level data across all packages
    left join nvd_signals nvd on ak.cve_id = nvd.cve_id
    left join osv_signals osv on ak.advisory_id = osv.advisory_id
    left join echo_signals echo on ak.advisory_id = echo.advisory_id
    left join source_contributions sc on ak.advisory_id = sc.advisory_id
)

select * from enriched
