-- Staging model for OSV observations
-- Normalizes OSV API data with fix information

with source as (
    select * from {{ source('raw', 'raw_osv_observations') }}
),

cleaned as (
    select
        observation_id,
        upper(trim(cve_id)) as cve_id,
        lower(trim(package_name)) as package_name,
        observed_at,
        raw_payload,
        coalesce(fix_available, false) as fix_available,
        nullif(trim(fixed_version), '') as fixed_version,
        "references",
        notes,
        run_id

    from source
    where cve_id is not null or package_name is not null
)

select * from cleaned
