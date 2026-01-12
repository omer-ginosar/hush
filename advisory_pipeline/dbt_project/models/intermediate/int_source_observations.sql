-- Unified source observations across all sources
-- Normalizes all sources into a common schema with source priority

with echo_advisories as (
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
        null::boolean as fix_available,
        null::varchar as fixed_version,
        notes,
        run_id
    from {{ ref('stg_echo_advisories') }}
    where not has_invalid_cve
),

echo_csv as (
    select
        observation_id,
        'echo_csv' as source_id,
        cve_id,
        package_name,
        observed_at,
        source_updated_at,
        null::varchar as status,
        override_status,
        override_reason,
        null::varchar as rejection_status,
        null::double as cvss_score,
        null::varchar as cvss_vector,
        null::boolean as fix_available,
        null::varchar as fixed_version,
        null::varchar as notes,
        run_id
    from {{ ref('stg_echo_csv') }}
),

nvd as (
    select
        observation_id,
        'nvd' as source_id,
        cve_id,
        null::varchar as package_name,
        observed_at,
        null::timestamp as source_updated_at,
        null::varchar as status,
        null::varchar as override_status,
        null::varchar as override_reason,
        rejection_status,
        cvss_score,
        cvss_vector,
        null::boolean as fix_available,
        null::varchar as fixed_version,
        notes,
        run_id
    from {{ ref('stg_nvd_observations') }}
),

osv as (
    select
        observation_id,
        'osv' as source_id,
        cve_id,
        package_name,
        observed_at,
        null::timestamp as source_updated_at,
        null::varchar as status,
        null::varchar as override_status,
        null::varchar as override_reason,
        null::varchar as rejection_status,
        null::double as cvss_score,
        null::varchar as cvss_vector,
        fix_available,
        fixed_version,
        notes,
        run_id
    from {{ ref('stg_osv_observations') }}
),

unioned as (
    select * from echo_advisories
    union all
    select * from echo_csv
    union all
    select * from nvd
    union all
    select * from osv
)

select
    *,
    -- Source priority for conflict resolution (lower = higher priority)
    case source_id
        when 'echo_csv' then 0  -- Internal overrides have highest priority
        when 'nvd' then 1        -- NVD is authoritative for CVE metadata
        when 'osv' then 2        -- OSV has good fix information
        when 'echo_data' then 3  -- Base data has lowest priority
        else 99
    end as source_priority
from unioned
