-- Current advisory state view
-- This is what gets published as advisory_current.json

with decisions as (
    select * from {{ ref('mart_advisory_decisions') }}
),

with_explanations as (
    select
        d.*,

        -- Generate human-readable explanation using macro
        {{ generate_explanation('d.reason_code', 'd.evidence') }} as explanation

    from decisions d
)

select
    advisory_id,
    cve_id,
    package_name,
    state,
    state_type,
    fixed_version,
    confidence,
    explanation,
    reason_code,
    evidence,
    decision_rule,
    contributing_sources,
    dissenting_sources,
    staleness_score,
    decided_at,
    run_id
from with_explanations
