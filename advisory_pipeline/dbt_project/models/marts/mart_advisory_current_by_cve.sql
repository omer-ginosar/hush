-- CVE-level deduplicated view of advisory state
-- Aggregates package-level advisories into a single row per CVE
-- Uses "worst state wins" priority for conflict resolution

with package_level as (
    select * from {{ ref('mart_advisory_current') }}
),

-- Define state priority (lower = worse state, higher priority)
-- Priority logic: non-final states > final states, and ordered by urgency
with_state_priority as (
    select
        *,
        case state
            -- Non-final states (highest priority - need action)
            when 'under_investigation' then 1
            when 'pending_upstream' then 2

            -- Final states (resolved)
            when 'wont_fix' then 3
            when 'not_applicable' then 4
            when 'fixed' then 5

            else 99
        end as state_priority
    from package_level
),

-- Rank entries per CVE by state priority, then by fixed_version availability
ranked as (
    select
        *,
        row_number() over (
            partition by cve_id
            order by
                state_priority asc,  -- Worst state wins
                fixed_version desc nulls last,  -- Prefer entries with fix info
                package_name nulls last  -- Prefer package-specific over CVE-only
        ) as rn
    from with_state_priority
),

-- Select the "primary" entry for each CVE
primary_entry as (
    select * from ranked where rn = 1
),

-- Collect all contributing packages for each CVE
contributing_packages as (
    select
        cve_id,
        list(distinct package_name order by package_name) filter (where package_name is not null) as affected_packages,
        count(distinct case when package_name is not null then package_name end) as package_count
    from package_level
    group by cve_id
),

-- Final deduplicated view
deduplicated as (
    select
        -- Use CVE as the unique identifier
        pe.cve_id as advisory_id,
        pe.cve_id,

        -- Package information: show all affected packages
        cp.affected_packages,
        cp.package_count,

        -- Primary package (from highest priority entry)
        pe.package_name as primary_package,

        -- State information from primary entry
        pe.state,
        pe.state_type,
        pe.fixed_version,
        pe.confidence,
        pe.explanation,
        pe.reason_code,

        -- Metadata
        pe.evidence,
        pe.decision_rule,
        pe.contributing_sources,
        pe.dissenting_sources,
        pe.staleness_score,
        pe.decided_at,
        pe.run_id,

        -- Add note about aggregation
        case
            when cp.package_count > 1 then
                'This CVE affects ' || cp.package_count::varchar || ' packages. ' ||
                'Showing state for primary package: ' || coalesce(pe.package_name, 'N/A') || '. ' ||
                pe.explanation
            else
                pe.explanation
        end as explanation_with_context

    from primary_entry pe
    inner join contributing_packages cp on pe.cve_id = cp.cve_id
)

select * from deduplicated
