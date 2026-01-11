-- Decision engine: Apply rule chain to determine advisory state
-- Each advisory gets exactly one state based on first matching rule

with inputs as (
    select * from {{ ref('int_decision_inputs') }}
),

decisions as (
    select
        advisory_id,
        cve_id,
        package_name,

        -- Apply rule chain (first match wins, by priority)
        case
            -- Rule 0: CSV Override (Priority 0)
            when override_status = 'not_applicable' then 'not_applicable'

            -- Rule 1: NVD Rejected (Priority 1)
            when is_rejected then 'not_applicable'

            -- Rule 2: Upstream Fix (Priority 2)
            when fix_available and fixed_version is not null then 'fixed'

            -- Rule 3: Distro Not Affected - would need distro data
            -- Skipped in prototype

            -- Rule 4: Distro Won't Fix - would need distro data
            -- Skipped in prototype

            -- Rule 5: Under Investigation (new CVE, no signals)
            when not has_signal then 'under_investigation'

            -- Rule 6: Default - Pending Upstream
            else 'pending_upstream'
        end as state,

        -- Determine which rule fired
        case
            when override_status = 'not_applicable' then 'R0:csv_override'
            when is_rejected then 'R1:nvd_rejected'
            when fix_available and fixed_version is not null then 'R2:upstream_fix'
            when not has_signal then 'R5:under_investigation'
            else 'R6:pending_upstream'
        end as decision_rule,

        -- Reason code for explanation templates
        case
            when override_status = 'not_applicable' then 'CSV_OVERRIDE'
            when is_rejected then 'NVD_REJECTED'
            when fix_available and fixed_version is not null then 'UPSTREAM_FIX'
            when not has_signal then 'NEW_CVE'
            else 'AWAITING_FIX'
        end as reason_code,

        -- State type (final vs non-final)
        case
            when override_status = 'not_applicable' then 'final'
            when is_rejected then 'final'
            when fix_available and fixed_version is not null then 'final'
            else 'non_final'
        end as state_type,

        -- Fixed version (only relevant for 'fixed' state)
        case
            when fix_available and fixed_version is not null then fixed_version
            else null
        end as fixed_version,

        confidence,

        -- Build evidence JSON with all relevant signals
        {
            'csv_override': override_status,
            'csv_reason': override_reason,
            'is_rejected': is_rejected,
            'fix_available': fix_available,
            'fixed_version': fixed_version,
            'cvss_score': cvss_score,
            'source_count': source_count
        } as evidence,

        contributing_sources,

        -- Dissenting sources (sources that disagree with final decision)
        -- Simplified: if CSV overrides as not_applicable but OSV says there's a fix
        case
            when override_status = 'not_applicable' and fix_available then
                ['osv']
            else
                []
        end as dissenting_sources,

        staleness_score,

        current_timestamp as decided_at,
        '{{ var("current_run_id") }}' as run_id

    from inputs
)

select * from decisions
