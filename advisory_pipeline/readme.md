# Advisory Pipeline - Technical Reference

Production-quality CVE advisory enrichment pipeline implementation.

## Quick Reference

```bash
# Run single pipeline execution
python3 run_pipeline.py

# Run multi-stage demonstration
python3 demo.py

# Run tests
pytest tests/ -v
```

**Outputs:**
- `output/advisory_current.json` - Current advisory states
- `output/run-report-*.md` - Execution metrics
- `advisory_pipeline.duckdb` - State history database

## Architecture

**Data Flow:**
```
Sources (Echo/NVD/OSV) → Adapters → Raw Tables → dbt → Marts → Rules → Decisions → SCD2 History
```

**Pipeline Stages:**
1. **Ingestion** - Fetch and normalize multi-source data
2. **Loading** - Write to raw DuckDB tables
3. **Transformation** - dbt staging → intermediate → marts
4. **State Tracking** - dbt snapshot for SCD Type 2 history
5. **Quality Checks** - Validate outputs
6. **Reporting** - Generate metrics and reports

## Components

### Ingestion ([ingestion/](ingestion/))

Adapters for each data source implementing `BaseAdapter` interface.

**Available Adapters:**
- `EchoDataAdapter` - Parse data.json (40k+ advisories)
- `EchoCsvAdapter` - Parse CSV overrides (analyst decisions)
- `NvdAdapter` - NVD vulnerability data (live API, optional mock)
- `OsvAdapter` - OSV vulnerability data (data dump, optional mock)

**Output:** Normalized `SourceObservation` objects

**See:** [ingestion/readme.md](ingestion/readme.md)

### Storage ([storage/](storage/))

Database schema management and data loading.

**Components:**
- `Database` - DuckDB schema initialization
- `SourceLoader` - Load observations into raw tables

**Tables:**
- `raw_echo_advisories` - Base corpus
- `raw_echo_csv` - Analyst overrides
- `raw_nvd_observations` - NVD data
- `raw_osv_observations` - OSV data
- `advisory_state_history` - SCD2 tracking
- `pipeline_runs` - Execution metadata

### dbt Project ([dbt_project/](dbt_project/))

SQL-based data transformations.

**Model Layers:**
1. **Staging** (`models/staging/`) - Validate and clean
2. **Intermediate** (`models/intermediate/`) - Enrich and aggregate
3. **Marts** (`models/marts/`) - Business outputs

**Key Models:**
- `stg_*` - Per-source validation
- `int_source_observations` - Unified source view
- `int_enriched_advisories` - Aggregated signals
- `mart_advisory_decisions` - Rule evaluations
- `mart_advisory_current` - Current states (PACKAGE-LEVEL)
- `mart_advisory_current_by_cve` - Deduplicated (CVE-LEVEL)
- `mart_advisory_state_history` - Historical state tracking (SCD2)

**Snapshots:**
- `advisory_state_snapshot` - dbt snapshot for SCD Type 2 tracking

**Important**: Use `mart_advisory_current_by_cve` for reporting/dashboards (one row per CVE).
Use `mart_advisory_current` for detailed analyst triage (package-level granularity).

**See:** [dbt_project/readme.md](dbt_project/readme.md)

### Decisioning ([decisioning/](decisioning/))

Rule-based decision engine with explainability.

**Components:**
- `Rule` - Abstract rule base class
- `RuleEngine` - First-match-wins evaluation
- `AdvisoryStateMachine` - Transition validation
- `ExplanationGenerator` - Template-based explanations

**Rules (Priority Order):**
- **R0** CSV Override → `not_applicable`
- **R1** NVD Rejected → `not_applicable`
- **R2** Upstream Fix → `fixed`
- **R5** Under Investigation → `under_investigation`
- **R6** Pending Upstream → `pending_upstream`

**See:** [decisioning/readme.md](decisioning/readme.md)

### Observability ([observability/](observability/))

Metrics collection and quality validation.

**Components:**
- `RunMetrics` - Execution metrics tracking
- `QualityChecker` - SQL-based data quality checks
- `RunReporter` - Markdown report generation

**Quality Checks:**
- `no_null_states` - All advisories have states
- `explanation_completeness` - All have explanations
- `fixed_has_version` - Fixed state has version
- `cve_format` - Valid CVE ID format
- `stalled_cves` - Detect stale states

**See:** [observability/readme.md](observability/readme.md)

## Configuration

All pipeline behavior configured via [config.yaml](config.yaml):

```yaml
database:
  path: "advisory_pipeline.duckdb"

sources:
  echo_data:
    type: "json"
    cache_path: "../data/data.json"  # Adjust path as needed

  echo_csv:
    path: "../data/advisory-not-applicable.csv"

  nvd:
    type: "api"
    base_url: "https://services.nvd.nist.gov/rest/json/cves/2.0"
    api_key_env: "NVD_API_KEY"
    days_back: 30
    max_records: 5000
    use_mock: false
    mock_file: "ingestion/mock_responses/nvd_responses.json"

  osv:
    type: "api"
    data_dump_url: "https://osv-vulnerabilities.storage.googleapis.com/all.zip"
    cache_dir: "ingestion/cache/osv"
    cache_ttl_hours: 24
    ecosystems: []
    max_records: 5000
    use_mock: false
    mock_file: "ingestion/mock_responses/osv_responses.json"

rules:
  - id: "R0"
    name: "csv_override"
    priority: 0
    reason_code: "CSV_OVERRIDE"

states:
  final:
    - "fixed"
    - "not_applicable"
  non_final:
    - "pending_upstream"
    - "under_investigation"
```

Set `NVD_API_KEY` in the environment for higher NVD rate limits. OSV data dump
downloads are cached under `ingestion/cache/osv` by default.

## Testing

Test suite in [tests/](tests/) with 67 passing tests.

**Organization:**
- **Unit Tests** - Individual component logic
- **Integration Tests** - Component interactions
- **Fixtures** - Shared test data in `conftest.py`

**Run Tests:**
```bash
# All tests
pytest tests/ -v

# Specific module
pytest tests/test_rule_engine.py -v

# With coverage
pytest tests/ --cov=advisory_pipeline --cov-report=html

# Integration only
pytest tests/test_integration.py tests/test_conflict_resolution.py -v
```

**See:** [tests/readme.md](tests/readme.md)

## Data Models

### SourceObservation

Normalized observation from any source.

```python
@dataclass
class SourceObservation:
    observation_id: str
    source_id: str                    # 'echo_data' | 'echo_csv' | 'nvd' | 'osv'
    cve_id: Optional[str]
    package_name: Optional[str]
    observed_at: datetime
    raw_payload: Dict[str, Any]
    # Normalized signals
    fix_available: Optional[bool]
    fixed_version: Optional[str]
    status: Optional[str]
    rejection_status: Optional[str]
    cvss_score: Optional[float]
```

### Decision

Rule engine output with explainability.

```python
@dataclass
class Decision:
    state: str                        # 'fixed' | 'not_applicable' | ...
    state_type: str                   # 'final' | 'non_final'
    confidence: str                   # 'high' | 'medium' | 'low'
    fixed_version: Optional[str]
    reason_code: str                  # 'CSV_OVERRIDE' | 'UPSTREAM_FIX' | ...
    explanation: str                  # Human-readable
    evidence: Dict[str, Any]          # Supporting data
    contributing_sources: List[str]   # Sources that contributed
    dissenting_sources: List[str]     # Sources that disagree
```

## Extending the Pipeline

### Add New Data Source

1. Implement `BaseAdapter` in `ingestion/new_source_adapter.py`
2. Add table schema in `storage/database.py`
3. Add loader method in `storage/loader.py`
4. Create dbt staging model `dbt_project/models/staging/stg_new_source.sql`
5. Update `int_source_observations.sql` to union new source
6. Add tests

### Add New Decision Rule

1. Implement `Rule` subclass in `decisioning/rules.py`
2. Add rule config to `config.yaml`
3. Add explanation template to config
4. Register in `RuleEngine._get_default_rules()`
5. Add tests in `tests/test_decisioning_rules.py`

### Add New Quality Check

1. Add method to `QualityChecker` class
2. Implement SQL-based validation
3. Add to `run_all_checks()` method
4. Add test in `tests/test_observability.py`

**See:** [development.md](../docs/phase-11/development.md) for detailed extension guide

## Pipeline Execution

### run_pipeline.py

Main orchestrator - runs full pipeline end-to-end.

**Execution Flow:**
1. Initialize database schema
2. Fetch from all sources
3. Load to raw tables
4. Run dbt transformations
5. Export current state JSON
6. Run quality checks
7. Generate markdown report

**Idempotency:** Safe to re-run (keyed by run_id)

### demo.py

Multi-run demonstration with visual CVE journey tracking.

**Features:**
- 3 progressive runs showing state changes
- Visual CVE journey tracker (icons, formatting)
- SCD2 history table display
- State distribution metrics

**See:** [demo.md](demo.md)

## State Change Tracking (SCD2)

Slowly Changing Dimension Type 2 pattern tracks full advisory history.

**Schema:**
```sql
advisory_state_history (
    history_id,
    advisory_id,
    state,
    effective_from,
    effective_to,      -- NULL for current
    is_current,
    -- metadata fields
)
```

**Query current state:**
```sql
SELECT * FROM advisory_state_history WHERE is_current = TRUE
```

**Query point-in-time:**
```sql
SELECT * FROM advisory_state_history
WHERE advisory_id = 'pkg:CVE-2024-0001'
  AND effective_from <= '2024-01-15'
  AND (effective_to IS NULL OR effective_to > '2024-01-15')
```

## Known Limitations

1. **OSV Dump Size**: Full data dump with local cache; use filters or max limits for scale
2. **Sequential Processing**: No parallelization
3. **Incremental Loads**: NVD supports time windows but no persisted checkpoints
4. **Single Environment**: No dev/staging/prod configs
5. **SCD2 Population**: Currently bypassed (dbt writes directly to marts)

**See:** [docs/implementation-status.md](../docs/implementation-status.md) for technical debt

## Dependencies

From [requirements.txt](requirements.txt):

```
dbt-duckdb>=1.7.0    # dbt with DuckDB adapter
duckdb>=0.9.0        # Embedded analytical database
pyyaml>=6.0          # Config parsing
requests>=2.31.0     # HTTP client for source APIs
jinja2>=3.1.0        # Template rendering
pytest>=7.4.0        # Testing framework
tabulate>=0.9.0      # Report formatting
```

## Project History

Phased development approach:
- **Phase 1**: Project setup and configuration
- **Phase 2**: Ingestion adapters
- **Phase 3**: Storage layer
- **Phase 4**: dbt transformations
- **Phase 5**: Decisioning engine
- **Phase 6**: Observability
- **Phase 7**: Orchestration
- **Phase 8**: Demo enhancements
- **Phase 9**: Test suite
- **Phase 10**: Documentation (this phase)

**Full history:** [docs/implementation-status.md](../docs/implementation-status.md)

## Interface Contracts

**Ingestion → Storage:**
```python
List[SourceObservation] → loader.load_*() → DuckDB raw tables
```

**Storage → dbt:**
```sql
Raw tables → dbt models → Mart tables
```

**dbt → Decisioning:**
```python
mart_advisory_decisions → RuleEngine → Decision objects
```

**Observability:**
```python
Database + RunMetrics → QualityChecker + Reporter → JSON + Markdown
```

## Troubleshooting

### Pipeline Fails on dbt

```bash
# Check dbt can find database
cd dbt_project
dbt debug

# Manually run dbt
dbt run --select stg_echo_advisories
```

### No Observations Loaded

```bash
# Check data files exist
ls -lh ../data/data.json
ls -lh ../data/advisory-not-applicable.csv

# Test adapter directly
python3 -c "from ingestion import EchoDataAdapter; ..."
```

### Quality Checks Fail

```bash
# Inspect failed data in DuckDB
duckdb advisory_pipeline.duckdb
SELECT * FROM mart_advisory_current WHERE state IS NULL;
```

### Empty SCD2 History

Known issue - pipeline doesn't populate `advisory_state_history`. State changes tracked in dbt snapshots (future enhancement).

---

**For Users:** See [../readme.md](../readme.md) for quick start
**For Developers:** See [../docs/phase-11/development.md](../docs/phase-11/development.md) for extension guide
**For Status:** See [../docs/implementation-status.md](../docs/implementation-status.md)
