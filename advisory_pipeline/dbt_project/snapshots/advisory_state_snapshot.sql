{% snapshot advisory_state_snapshot %}

{{
    config(
      target_schema='main',
      unique_key='advisory_id',
      strategy='check',
      check_cols=['state', 'fixed_version', 'confidence', 'reason_code', 'explanation'],
      invalidate_hard_deletes=True
    )
}}

-- Source: mart_advisory_current
-- This snapshot tracks state changes over time using dbt's SCD Type 2 implementation
-- Changes are detected when any of the check_cols values change

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
    run_id
from {{ ref('mart_advisory_current') }}

{% endsnapshot %}
