# dbt Project - Phase 4: Data Transformations

## Overview

This dbt project implements the data transformation layer for the CVE Advisory Pipeline. It transforms raw source observations into actionable advisory decisions using a rule-based decision engine.

## Architecture

The project follows a medallion architecture pattern:

```
Raw Data (Python) → Staging (dbt views) → Intermediate (dbt tables) → Marts (dbt tables)
```

### Data Flow

1. **Raw Layer** (managed by Python adapters in Phase 2-3):
   - `raw_echo_advisories` - Base advisory corpus
   - `raw_echo_csv` - Analyst overrides
   - `raw_nvd_observations` - NVD data
   - `raw_osv_observations` - OSV data

2. **Staging Layer** (dbt views):
   - `stg_echo_advisories` - Cleaned Echo data
   - `stg_echo_csv` - Cleaned CSV overrides
   - `stg_nvd_observations` - Cleaned NVD data with severity
   - `stg_osv_observations` - Cleaned OSV data with fix info

3. **Intermediate Layer** (dbt tables):
   - `int_source_observations` - Unified observations with source priority
   - `int_enriched_advisories` - Aggregated signals with conflict resolution
   - `int_decision_inputs` - Prepared inputs for rule engine

4. **Mart Layer** (dbt tables):
   - `mart_advisory_decisions` - Rule-based state decisions
   - `mart_advisory_current` - Current states with explanations

## Decision Rules

The decision engine applies rules in priority order (first match wins):

| Priority | Rule ID | Name | Reason Code | Final State |
|----------|---------|------|-------------|-------------|
| 0 | R0 | CSV Override | CSV_OVERRIDE | Yes |
| 1 | R1 | NVD Rejected | NVD_REJECTED | Yes |
| 2 | R2 | Upstream Fix | UPSTREAM_FIX | Yes |
| 5 | R5 | Under Investigation | NEW_CVE | No |
| 6 | R6 | Pending Upstream | AWAITING_FIX | No |

## Key Design Decisions

### 1. Source Priority for Conflict Resolution

When multiple sources provide conflicting information, we use this priority:

1. **echo_csv** (priority 0) - Internal analyst decisions override everything
2. **nvd** (priority 1) - Authoritative for CVE metadata and rejection status
3. **osv** (priority 2) - Best for fix availability and version information
4. **echo_data** (priority 3) - Base data, lowest priority

### 2. Advisory Identifier

Advisories are uniquely identified by: `package_name:CVE_ID`

This ensures we track CVE impact per package, not just per CVE.

### 3. Materialization Strategy

- **Staging**: Views (cheap, always fresh)
- **Intermediate**: Tables (reused by multiple downstream models)
- **Marts**: Tables (optimized for consumption)

### 4. State Types

States are classified as:
- **final**: Decision is definitive (fixed, not_applicable, wont_fix)
- **non_final**: Decision may change (pending_upstream, under_investigation)

## Running the dbt Project

### Prerequisites

```bash
# Install dependencies (from project root)
pip install -r requirements.txt
```

### Basic Commands

```bash
# Navigate to dbt project
cd advisory_pipeline/dbt_project

# Run all models
dbt run

# Run tests
dbt test

# Generate and serve documentation
dbt docs generate
dbt docs serve
```

### Incremental Runs

```bash
# Run only changed models
dbt run --select state:modified+

# Run specific model and downstream
dbt run --select mart_advisory_current+
```

## Testing

The project includes three types of tests:

### 1. Schema Tests (in .yml files)
- Uniqueness constraints
- Not null constraints
- Accepted value checks
- Referential integrity

### 2. Data Tests (in tests/)
- `assert_all_advisories_have_decisions.sql` - Completeness check
- `assert_no_duplicate_decisions.sql` - Uniqueness check
- `assert_final_states_have_evidence.sql` - Quality check

### 3. Running Tests

```bash
# Run all tests
dbt test

# Run tests for specific model
dbt test --select mart_advisory_current
```

## Macros

### `generate_explanation(reason_code, evidence)`

Generates human-readable explanations from reason codes and evidence.

**Usage:**
```sql
{{ generate_explanation('d.reason_code', 'd.evidence') }} as explanation
```

## Integration with Python Pipeline

The dbt project is designed to be invoked by the Python orchestrator:

```python
import subprocess
import os

# Set run ID for tracking
os.environ['PIPELINE_RUN_ID'] = 'run_20240111_120000'

# Run dbt models
subprocess.run(['dbt', 'run'], cwd='dbt_project', check=True)

# Run dbt tests
subprocess.run(['dbt', 'test'], cwd='dbt_project', check=True)
```

## Output Tables

### `mart_advisory_current`

This is the primary output table for consumption:

```sql
select
    advisory_id,        -- 'package_name:CVE-2024-1234'
    cve_id,             -- 'CVE-2024-1234'
    package_name,       -- 'example-package'
    state,              -- 'fixed' | 'not_applicable' | ...
    state_type,         -- 'final' | 'non_final'
    fixed_version,      -- '1.2.3' (if applicable)
    confidence,         -- 'high' | 'medium' | 'low'
    explanation,        -- Human-readable text
    reason_code,        -- 'UPSTREAM_FIX'
    decision_rule,      -- 'R2:upstream_fix'
    evidence            -- JSON with supporting data
from mart_advisory_current
```

## Known Limitations

1. **Staleness Scoring**: Currently simplified (always 0.0). Production would calculate based on last observation time.

2. **Distro-Specific Rules**: Rules R3 (distro_not_affected) and R4 (distro_wont_fix) are not implemented as we don't have distro-specific data sources.

3. **No SCD2 Snapshot**: The `advisory_state_history` table exists but is not yet populated by dbt snapshots. This will be added in future phases.

4. **Limited Conflict Detection**: Dissenting sources are only tracked in simple cases (CSV override vs OSV fix).

## Future Enhancements

1. Add dbt snapshots for SCD Type 2 tracking
2. Implement staleness calculation based on temporal analysis
3. Add more sophisticated conflict resolution logic
4. Create additional mart views for specific use cases (high severity, recently changed, etc.)
5. Add incremental model support for performance

## Troubleshooting

### "Relation does not exist"

Ensure the Python pipeline has run at least once to create raw tables:

```bash
cd ..
python -c "from storage.database import Database; db = Database(); db.initialize_schema()"
```

### "No such environment variable"

Set the `PIPELINE_RUN_ID` environment variable:

```bash
export PIPELINE_RUN_ID=manual_run
dbt run
```

### Performance Issues

If models are slow:

1. Check intermediate table materialization
2. Consider adding indexes on advisory_id and cve_id
3. Use `dbt run --select <model>` for targeted runs

## Contact

For questions about this dbt project, see the main project README or implementation plan.
