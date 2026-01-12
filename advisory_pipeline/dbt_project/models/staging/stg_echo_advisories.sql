-- Staging model for Echo base advisories
-- Validates and cleans raw data from data.json

with source as (
    select * from {{ source('raw', 'raw_echo_advisories') }}
),

validated as (
    select
        observation_id,
        -- Validate CVE ID format (CVE-YYYY-NNNNN)
        case
            when cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$' then cve_id
            else null
        end as cve_id,
        nullif(trim(package_name), '') as package_name,
        observed_at,
        raw_payload,
        lower(trim(status)) as status,
        fix_available,
        fixed_version,
        cvss_score,
        notes,
        run_id,

        -- Flag invalid records for observability
        case when cve_id !~ '^CVE-[0-9]{4}-[0-9]{4,}$' then true else false end as has_invalid_cve

    from source
    where package_name is not null
      and trim(package_name) != ''
)

select * from validated
