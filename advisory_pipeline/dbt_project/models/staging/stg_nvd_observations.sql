-- Staging model for NVD observations
-- Normalizes NVD API data

with source as (
    select * from {{ source('raw', 'raw_nvd_observations') }}
),

cleaned as (
    select
        observation_id,
        upper(trim(cve_id)) as cve_id,
        observed_at,
        raw_payload,
        lower(trim(rejection_status)) as rejection_status,
        cvss_score,
        cvss_vector,
        "references",
        notes,
        run_id,

        -- Derive severity from CVSS score
        case
            when cvss_score >= 9.0 then 'critical'
            when cvss_score >= 7.0 then 'high'
            when cvss_score >= 4.0 then 'medium'
            when cvss_score >= 0.1 then 'low'
            else 'none'
        end as severity

    from source
    where cve_id is not null
)

select * from cleaned
