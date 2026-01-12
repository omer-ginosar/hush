-- depends_on: {{ ref('advisory_state_snapshot') }}
-- Advisory state history (SCD Type 2)
-- Maps dbt snapshot output to advisory_state_history schema
-- This provides the historical state tracking required for audit and analysis
--
-- Note: This model runs AFTER snapshots in a separate dbt run step.
-- It reads from the advisory_state_snapshot table created by dbt snapshot.

{{
    config(
        materialized='table',
        alias='advisory_state_history'
    )
}}

-- Read from the snapshot table (using direct table reference since it's created by snapshot, not a model)
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

from main.advisory_state_snapshot
