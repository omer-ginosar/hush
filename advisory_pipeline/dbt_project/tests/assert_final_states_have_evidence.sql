-- Test: Ensure final states have supporting evidence
-- Final decisions should have at least one piece of evidence

with final_decisions as (
    select
        advisory_id,
        state,
        state_type,
        evidence
    from {{ ref('mart_advisory_decisions') }}
    where state_type = 'final'
),

missing_evidence as (
    select
        advisory_id,
        state
    from final_decisions
    where evidence is null
       or (
           evidence['csv_override'] is null
           and evidence['is_rejected'] = false
           and evidence['fix_available'] = false
       )
)

-- Test passes if all final states have evidence
select * from missing_evidence
