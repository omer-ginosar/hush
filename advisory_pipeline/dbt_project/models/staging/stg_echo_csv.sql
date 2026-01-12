-- Staging model for Echo CSV overrides
-- Internal analyst decisions that override upstream sources

with source as (
    select * from {{ source('raw', 'raw_echo_csv') }}
),

cleaned as (
    select
        observation_id,
        upper(trim(cve_id)) as cve_id,
        -- Allow NULL package_name for CVE-only overrides (e.g., NVD-only CVEs)
        nullif(lower(trim(package_name)), '') as package_name,
        observed_at,
        source_updated_at,
        raw_payload,
        lower(trim(status)) as override_status,
        reason as override_reason,
        run_id

    from source
    -- Only require CVE ID, package_name is optional
    where cve_id is not null
      and trim(cve_id) != ''
)

select * from cleaned
