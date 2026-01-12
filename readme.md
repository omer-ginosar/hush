# 🌑 Hush - CVE Advisory Pipeline

CVE advisory enrichment pipeline prototype built with Python, DuckDB, and dbt.

## Overview

This pipeline ingests security advisories from multiple sources (Echo's internal data, NVD, OSV), applies deterministic business rules, and produces enriched advisory states with full explainability and state change history.

**Key Features:**
- Multi-source ingestion with conflict resolution
- Deterministic rule-based decision engine
- SCD Type 2 state history tracking
- dbt-based data transformations
- Comprehensive observability and quality checks
- Full explainability for every decision

## Quick Start

### Prerequisites

- Python 3.11+
- Input data files in `data/`:
  - `data/data.json` (Echo advisory corpus)
  - `data/advisory-not-applicable.csv` (analyst overrides)
  - `data/data-sample.json` (optional sample subset)

### Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
cd advisory_pipeline
pip install -r requirements.txt
```

### Run the Pipeline

```bash
# Single run
python3 run_pipeline.py

# Multi-run demonstration with visual CVE tracking
python3 demo.py
```

Optional: provide an NVD API key for higher rate limits:
```bash
export NVD_API_KEY="your-key"
```

### Outputs

- `output/advisory_current.json` - Current state of all advisories
- `output/run-report-*.md` - Execution metrics and quality checks
- `advisory_pipeline.duckdb` - Full state history database

## Architecture

```
Source Files → Ingestion Adapters → Raw Tables (DuckDB)
                                          ↓
                               dbt Transformations
                                          ↓
                            Enriched Advisory Data
                                          ↓
                          Rule Engine + Decisioning
                                          ↓
                        SCD2 State History + Outputs
```

**Components:**
- **Ingestion** ([advisory_pipeline/ingestion](advisory_pipeline/ingestion)) - Source adapters for Echo, NVD, OSV
- **Storage** ([advisory_pipeline/storage](advisory_pipeline/storage)) - DuckDB schema and data loading
- **dbt** ([advisory_pipeline/dbt_project](advisory_pipeline/dbt_project)) - SQL transformations (staging → marts)
- **Decisioning** ([advisory_pipeline/decisioning](advisory_pipeline/decisioning)) - Priority-ordered rule engine
- **Observability** ([advisory_pipeline/observability](advisory_pipeline/observability)) - Metrics and quality checks

## Rule-Based Decision Engine

Advisories are evaluated through a priority-ordered rule chain:

| Priority | Rule | State | Trigger |
|----------|------|-------|---------|
| 0 | CSV Override | `not_applicable` | Internal analyst decision |
| 1 | NVD Rejected | `not_applicable` | CVE rejected by NVD |
| 2 | Upstream Fix | `fixed` | Fix version available |
| 5 | Under Investigation | `under_investigation` | New CVE, no signals |
| 6 | Pending Upstream | `pending_upstream` | Default fallback |

Every decision includes:
- State assignment (`fixed`, `not_applicable`, `pending_upstream`, etc.)
- Confidence level (`high`, `medium`, `low`)
- Reason code and human-readable explanation
- Supporting evidence from all sources
- Contributing and dissenting sources

## State Change Tracking

Uses **SCD Type 2** (Slowly Changing Dimension) pattern to track advisory state history:
- Full history of all state changes
- Temporal queries (`effective_from`, `effective_to`)
- Point-in-time snapshots
- Audit trail for every decision

## Testing

```bash
# Run all tests
cd advisory_pipeline
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=advisory_pipeline --cov-report=html

# Integration tests only
pytest tests/test_integration.py tests/test_conflict_resolution.py -v
```

**Test Coverage:**
- 22 integration tests (conflict resolution, end-to-end)
- 45+ unit tests (adapters, rules, state machine, explainer)
- Test fixtures and mocks for isolated testing

See [advisory_pipeline/tests/readme.md](advisory_pipeline/tests/readme.md) for details.

## Project Structure

```
hush/
├── readme.md                           # This file
├── data/                               # Input datasets (local)
├── advisory_pipeline/
│   ├── readme.md                       # Technical documentation
│   ├── config.yaml                     # Pipeline configuration
│   ├── run_pipeline.py                 # Main orchestrator
│   ├── demo.py                         # Visual demonstration
│   ├── ingestion/                      # Source adapters
│   ├── storage/                        # Database layer
│   ├── dbt_project/                    # SQL transformations
│   ├── decisioning/                    # Rule engine
│   ├── observability/                  # Metrics & quality
│   ├── tests/                          # Test suite
│   └── output/                         # Generated reports
└── docs/
    ├── assets/                          # Design artifacts
    ├── phase-11/                        # Phase handoff docs
    ├── implementation-status.md
    ├── prototype-implementation-plan.md
    └── raw-design.md
```

## Documentation

### Docs Index
- [docs/implementation-status.md](docs/implementation-status.md) - Phase completion status
- [docs/prototype-implementation-plan.md](docs/prototype-implementation-plan.md) - Original plan
- [docs/raw-design.md](docs/raw-design.md) - Design discussions
- [docs/phase-11/](docs/phase-11) - Phase handoff artifacts
- [docs/assets/](docs/assets) - Design diagrams and source files

### For Users
- [Quick Start](#quick-start) (this file)
- [demo.md](advisory_pipeline/demo.md) - Visual demonstration guide

### For Developers
- [docs/phase-11/development.md](docs/phase-11/development.md) - Development workflow and conventions
- [advisory_pipeline/readme.md](advisory_pipeline/readme.md) - Technical reference
- [Tests README](advisory_pipeline/tests/readme.md) - Testing guide

### For Agents
- [docs/implementation-status.md](docs/implementation-status.md) - Phase completion status
- Component READMEs in each module directory

### Architecture & Design
- [docs/prototype-implementation-plan.md](docs/prototype-implementation-plan.md) - Original plan
- [docs/raw-design.md](docs/raw-design.md) - Design discussions

## Configuration

Pipeline behavior is controlled via [advisory_pipeline/config.yaml](advisory_pipeline/config.yaml):

- **Data Sources**: File paths and API configurations
- **Rules**: Priority-ordered decision rules
- **States**: Final vs non-final state classification
- **Explanation Templates**: Human-readable text patterns

## Known Limitations

1. **OSV Dump Size**: Full data dump with local cache; use filters or max limits for scale
2. **Single Environment**: No dev/staging/prod config separation
3. **Incremental Processing**: NVD uses time windows but no persisted checkpoints
4. **Sequential Processing**: No parallelization of source fetching

See [docs/implementation-status.md](docs/implementation-status.md) for technical debt tracking.

## Contributing

This is a technical assessment prototype. For production deployment:

1. Persist incremental checkpoints per source
2. Expand OSV filtering strategy or use per-ecosystem dumps
3. Add distributed orchestration (Airflow, etc.)
4. Add centralized caching (Redis) for source responses
5. Add service-level monitoring/alerting

## License

Internal prototype for Echo Data Engineering assessment.

---

**Status**: ✅ All 9 development phases complete
**Last Updated**: 2026-01-12
**Test Status**: 67 tests passing
