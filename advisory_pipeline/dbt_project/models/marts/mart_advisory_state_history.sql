-- Advisory state history (SCD Type 2)
-- Maps dbt snapshot output to advisory_state_history schema
-- This provides the historical state tracking required for audit and analysis

{% set snapshot_exists = run_query("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'main' AND table_name = 'advisory_state_snapshot'") %}

{% if execute and snapshot_exists.rows[0][0] > 0 %}

with snapshot as (
    select * from {{ ref('advisory_state_snapshot') }}
),

mapped as (
    select
        -- Generate history_id from dbt_scd_id
        dbt_scd_id as history_id,

        -- Advisory identifiers
        advisory_id,
        cve_id,
        package_name,

        -- State information
        state,
        state_type,
        fixed_version,
        confidence,
        explanation,
        reason_code,

        -- Evidence and decision metadata
        evidence,
        decision_rule,
        contributing_sources,
        dissenting_sources,

        -- SCD2 temporal columns (map dbt columns to our schema)
        dbt_valid_from as effective_from,
        dbt_valid_to as effective_to,

        -- Current record indicator
        case when dbt_valid_to is null then true else false end as is_current,

        -- Pipeline metadata
        run_id,
        staleness_score,

        -- Audit timestamp
        dbt_updated_at as created_at

    from snapshot
)

select * from mapped

{% else %}

-- If snapshot doesn't exist yet (first run), return empty result with correct schema
select
    cast(null as varchar) as history_id,
    cast(null as varchar) as advisory_id,
    cast(null as varchar) as cve_id,
    cast(null as varchar) as package_name,
    cast(null as varchar) as state,
    cast(null as varchar) as state_type,
    cast(null as varchar) as fixed_version,
    cast(null as varchar) as confidence,
    cast(null as varchar) as explanation,
    cast(null as varchar) as reason_code,
    cast(null as json) as evidence,
    cast(null as varchar) as decision_rule,
    cast(null as json) as contributing_sources,
    cast(null as json) as dissenting_sources,
    cast(null as timestamp) as effective_from,
    cast(null as timestamp) as effective_to,
    cast(null as boolean) as is_current,
    cast(null as varchar) as run_id,
    cast(null as double) as staleness_score,
    cast(null as timestamp) as created_at
where false

{% endif %}
