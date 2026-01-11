# Phase 7: Main Orchestrator

## Overview

Phase 7 delivers the main pipeline orchestrator that coordinates all previous phases into a cohesive, production-ready data pipeline. The orchestrator manages the complete advisory enrichment workflow from ingestion through quality checks and reporting.

## Components

### `run_pipeline.py`
Main orchestrator that executes the complete pipeline flow:

1. **Database Initialization**: Creates schema if not exists
2. **Source Ingestion**: Fetches observations from all configured sources
3. **Data Loading**: Stores raw observations in DuckDB landing zone
4. **dbt Transformations**: Executes staging → intermediate → marts
5. **Output Export**: Generates `advisory_current.json`
6. **Quality Checks**: Runs data validation suite
7. **Reporting**: Creates Markdown run reports

**Key Design Decisions:**
- **Idempotent**: Safe to re-run with same data
- **Observable**: Comprehensive logging and metrics at every stage
- **Deterministic**: Same inputs always produce same outputs
- **Fail-safe**: Errors logged but don't prevent quality checks

**Usage:**
```bash
cd advisory_pipeline
python run_pipeline.py [--config path/to/config.yaml]
```

### `demo.py`
Interactive demonstration script showing the pipeline across multiple runs:

**Scenarios:**
- **Run 1**: Initial load - establishes baseline state
- **Run 2**: CSV override - shows analyst override priority
- **Run 3**: Upstream fix - demonstrates fix detection and state transition

**Features:**
- Clean environment setup
- Mock data generation
- State history visualization
- Before/after comparisons

**Usage:**
```bash
cd advisory_pipeline
python demo.py
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     run_pipeline.py                         │
│                   (Main Orchestrator)                       │
└─────────────────────────────────────────────────────────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
        ▼                    ▼                    ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Ingestion   │    │   Storage    │    │ Decisioning  │
│   (Phase 2)  │───▶│   (Phase 3)  │───▶│  (Phase 5)   │
└──────────────┘    └──────────────┘    └──────────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
        ▼                    ▼                    ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  dbt Models  │    │ Observability│    │   Outputs    │
│   (Phase 4)  │    │   (Phase 6)  │    │   (JSON/MD)  │
└──────────────┘    └──────────────┘    └──────────────┘
```

## Execution Flow

### Stage 1: Database Initialization
- Creates DuckDB connection
- Initializes schema (raw tables, state history, indexes)
- Validates configuration

### Stage 2: Source Ingestion
For each source (echo_data, echo_csv, nvd, osv):
- Call adapter's `fetch()` method
- Load observations into raw tables
- Record source health metrics
- Handle errors gracefully (don't fail entire run)

### Stage 3: dbt Transformations
- Set `PIPELINE_RUN_ID` environment variable
- Execute `dbt run` in dbt_project directory
- Models run in dependency order:
  - Staging: Clean and normalize
  - Intermediate: Enrich and aggregate
  - Marts: Apply decision rules

### Stage 4: Output Export
- Query `mart_advisory_current` (dbt output)
- Convert to JSON with metadata
- Write to `output/advisory_current.json`

### Stage 5: Quality Checks
- Run validation suite (QualityChecker)
- Check for null states, missing explanations, etc.
- Record results in metrics

### Stage 6: Reporting
- Finalize run metrics
- Generate Markdown report with:
  - Summary statistics
  - State distribution
  - State transitions
  - Rules fired
  - Quality check results
  - Source health
- Save to `output/run_report_TIMESTAMP.md`

## Integration Points

### Phase 2 (Ingestion)
- Uses all four adapters: EchoDataAdapter, EchoCsvAdapter, NvdAdapter, OsvAdapter
- Expects `SourceObservation` objects from `fetch()`
- Calls `get_health()` for source status

### Phase 3 (Storage)
- Uses Database for connection management
- Uses SourceLoader for raw table loading
- Database manages schema initialization

### Phase 4 (dbt)
- Calls dbt CLI as subprocess
- Passes run_id via environment variable
- Expects dbt project in `dbt_project/` subdirectory
- Reads from `mart_advisory_current` view

### Phase 5 (Decisioning)
- **Not directly called by orchestrator**
- Decision logic is in dbt SQL models (Phase 4)
- Python decisioning layer available for future enhancements

### Phase 6 (Observability)
- Uses RunMetrics for tracking
- Uses QualityChecker for validation
- Uses RunReporter for output generation

## Configuration

The orchestrator reads from `config.yaml`:

```yaml
pipeline:
  name: "echo_advisory_pipeline"
  version: "0.1.0"

database:
  path: "advisory_pipeline.duckdb"

sources:
  echo_data:
    type: "json"
    cache_path: "../data.json"
  echo_csv:
    type: "csv"
    path: "../advisory_not_applicable.csv"
  nvd:
    type: "mock"
    mock_file: "ingestion/mock_responses/nvd_responses.json"
  osv:
    type: "mock"
    mock_file: "ingestion/mock_responses/osv_responses.json"
```

## Outputs

### advisory_current.json
Current state of all advisories:
```json
{
  "generated_at": "2024-01-11T12:00:00Z",
  "advisory_count": 42,
  "advisories": [
    {
      "advisory_id": "example-package:CVE-2024-0001",
      "cve_id": "CVE-2024-0001",
      "package_name": "example-package",
      "state": "fixed",
      "state_type": "final",
      "fixed_version": "1.2.3",
      "confidence": "high",
      "explanation": "Fixed in version 1.2.3. Fix available from upstream.",
      "reason_code": "UPSTREAM_FIX",
      "contributing_sources": ["osv", "nvd"],
      "dissenting_sources": []
    }
  ]
}
```

### run_report_TIMESTAMP.md
Markdown report with:
- Run metadata (ID, timestamp, duration)
- Summary table (advisories, changes, errors)
- State distribution
- State transitions
- Rules fired
- Quality check results
- Source health

## Error Handling

### Source Ingestion Failures
- Logged as warnings
- Recorded in metrics
- Marked in source health
- Pipeline continues with other sources

### dbt Failures
- Raise RuntimeError
- Halt pipeline execution
- Log stdout/stderr for debugging

### Quality Check Failures
- Recorded in report
- Don't halt execution
- Visible in summary output

## Testing

### Unit Tests
Each component has unit tests in adjacent phases.

### Integration Test
Run the demo script:
```bash
python demo.py
```

Expected output:
- 3 successful runs
- State transitions visible
- Output files generated

### Validation
Check outputs exist:
```bash
ls output/
# Should show:
#   advisory_current.json
#   run_report_20240111_120000.md
#   run_report_20240111_120030.md
#   run_report_20240111_120100.md
```

## Known Limitations

1. **No Parallel Processing**: Sources fetched sequentially
   - Future: Use ThreadPoolExecutor for concurrent fetching

2. **No Retry Logic**: Failed sources not retried
   - Future: Add exponential backoff for transient failures

3. **No Incremental Processing**: Full refresh every run
   - Future: Track last processed timestamps per source

4. **dbt Subprocess Call**: Not ideal for production
   - Future: Use dbt Python API when stable

5. **No State Rollback**: Failed runs leave partial state
   - Future: Transaction-based runs with rollback

## Future Enhancements

### Short Term
- [ ] Add `--dry-run` mode for validation without writes
- [ ] Support `--source` flag to run specific sources only
- [ ] Add progress indicators for long-running operations
- [ ] Generate HTML reports alongside Markdown

### Medium Term
- [ ] Implement incremental ingestion
- [ ] Add source retry with exponential backoff
- [ ] Parallel source fetching
- [ ] Support for custom dbt profiles

### Long Term
- [ ] Replace subprocess dbt calls with Python API
- [ ] Add transaction support for atomic runs
- [ ] Implement change data capture (CDC)
- [ ] Support for streaming ingestion

## Dependencies

- Python 3.11+
- dbt-duckdb >=1.7.0
- PyYAML >=6.0
- tabulate >=0.9.0
- All Phase 2-6 components

## Maintenance Notes

### Adding New Sources
1. Create adapter in `ingestion/`
2. Add to `config.yaml` under `sources`
3. Add initialization in `AdvisoryPipeline.__init__`
4. Add loader case in `_load_observations`

### Modifying Pipeline Flow
1. Update `AdvisoryPipeline.run()` method
2. Update this README's execution flow
3. Update integration tests
4. Update demo script if needed

### Changing Output Format
1. Modify `_export_current_state()` method
2. Update consumer documentation
3. Maintain backward compatibility or version the format

## Contact

For questions about the orchestrator implementation, see:
- Implementation plan: `docs/PROTOTYPE_IMPLEMENTATION_PLAN.md`
- Architecture guide: `docs/WHERE_TO_ADD_THINGS.md`
