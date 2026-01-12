-- Enriched advisories with aggregated signals from all sources
-- Implements conflict resolution logic

with observations as (
    select * from {{ ref('int_source_observations') }}
),

-- Get unique advisory identifiers (package:CVE combinations)
-- Note: NVD observations have NULL package_name and are CVE-only
-- To avoid collisions, we use CVE-only ID when package_name is NULL
advisory_keys as (
    select distinct
        case
            when package_name is not null then package_name || ':' || cve_id
            else cve_id  -- CVE-only advisory (from NVD)
        end as advisory_id,
        cve_id,
        package_name
    from observations
    where cve_id is not null
),

-- Aggregate CSV overrides (highest priority)
csv_overrides as (
    select
        case
            when package_name is not null then package_name || ':' || cve_id
            else cve_id
        end as advisory_id,
        override_status,
        override_reason,
        source_updated_at as csv_updated_at
    from observations
    where source_id = 'echo_csv'
      and override_status is not null
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

-- Aggregate OSV signals (package-level)
osv_signals as (
    select
        case
            when package_name is not null then package_name || ':' || cve_id
            else cve_id
        end as advisory_id,
        max(fix_available) as osv_fix_available,
        max(fixed_version) as osv_fixed_version,
        max(notes) as osv_summary
    from observations
    where source_id = 'osv'
    group by case
        when package_name is not null then package_name || ':' || cve_id
        else cve_id
    end
),

-- Aggregate echo_data signals (Echo's own advisory data with fixed versions)
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

-- List contributing sources per advisory
source_contributions as (
    select
        case
            when package_name is not null then package_name || ':' || cve_id
            else cve_id
        end as advisory_id,
        list(distinct source_id) as contributing_sources
    from observations
    where cve_id is not null
    group by case
        when package_name is not null then package_name || ':' || cve_id
        else cve_id
    end
),

-- Combine all signals
enriched as (
    select
        ak.advisory_id,
        ak.cve_id,
        ak.package_name,

        -- CSV override signals
        csv.override_status,
        csv.override_reason,
        csv.csv_updated_at,

        -- NVD signals
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

        -- CVSS: prefer NVD (authoritative)
        nvd.nvd_cvss_score as cvss_score,

        -- Is rejected: only from NVD
        nvd.nvd_rejection_status = 'rejected' as is_rejected,

        -- Contributing sources
        sc.contributing_sources,

        -- Calculate staleness (simplified - would use last_checked in production)
        0.0 as staleness_score

    from advisory_keys ak
    left join csv_overrides csv on ak.advisory_id = csv.advisory_id
    left join nvd_signals nvd on ak.cve_id = nvd.cve_id
    left join osv_signals osv on ak.advisory_id = osv.advisory_id
    left join echo_signals echo on ak.advisory_id = echo.advisory_id
    left join source_contributions sc on ak.advisory_id = sc.advisory_id
)

select * from enriched
