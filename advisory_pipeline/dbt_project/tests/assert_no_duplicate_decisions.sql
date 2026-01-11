-- Test: Ensure no duplicate decisions per advisory
-- Each advisory should have exactly one decision

with decision_counts as (
    select
        advisory_id,
        count(*) as decision_count
    from {{ ref('mart_advisory_decisions') }}
    group by advisory_id
    having count(*) > 1
)

-- Test passes if no duplicates
select * from decision_counts
