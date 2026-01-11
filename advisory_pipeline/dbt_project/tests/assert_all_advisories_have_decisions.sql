-- Test: Ensure all advisories from sources have corresponding decisions
-- This test fails if any advisory is missing from the final mart

with source_advisories as (
    select distinct
        coalesce(package_name, 'UNKNOWN') || ':' || cve_id as advisory_id
    from {{ ref('int_source_observations') }}
    where cve_id is not null
),

decisions as (
    select advisory_id
    from {{ ref('mart_advisory_decisions') }}
),

missing as (
    select s.advisory_id
    from source_advisories s
    left join decisions d on s.advisory_id = d.advisory_id
    where d.advisory_id is null
)

-- Test passes if no missing advisories
select * from missing
