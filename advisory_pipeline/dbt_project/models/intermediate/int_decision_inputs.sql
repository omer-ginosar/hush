-- Prepare inputs for decision engine
-- Adds derived fields needed by rule evaluation

with enriched as (
    select * from {{ ref('int_enriched_advisories') }}
),

with_derived as (
    select
        *,

        -- Confidence scoring based on signal quality
        case
            when override_status is not null then 'high'  -- Internal override = high confidence
            when fix_available and fixed_version is not null then 'high'
            when is_rejected then 'high'
            when cvss_score is not null then 'medium'
            else 'low'
        end as confidence,

        -- Count of sources with signals
        list_count(contributing_sources) as source_count,

        -- Has any substantive signal
        case
            when override_status is not null then true
            when is_rejected then true
            when fix_available then true
            when cvss_score is not null then true
            else false
        end as has_signal

    from enriched
)

select * from with_derived
