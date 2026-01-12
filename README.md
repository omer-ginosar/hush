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
- Input data files in project root:
  - `data.json` (Echo advisory corpus)
  - `advisory_not_applicable.csv` (analyst overrides)

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

### Outputs

- `output/advisory_current.json` - Current state of all advisories
- `output/run_report_*.md` - Execution metrics and quality checks
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

See [advisory_pipeline/tests/README.md](advisory_pipeline/tests/README.md) for details.

## Project Structure

```
hush/
├── README.md                           # This file
├── DEVELOPMENT.md                      # Developer/agent guide
├── advisory_pipeline/
│   ├── README.md                       # Technical documentation
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
    ├── PROTOTYPE_IMPLEMENTATION_PLAN.md
    ├── IMPLEMENTATION_STATUS.md
    └── [phase handoff documents]
```

## Documentation

### For Users
- [Quick Start](#quick-start) (this file)
- [DEMO.md](advisory_pipeline/DEMO.md) - Visual demonstration guide

### For Developers
- [DEVELOPMENT.md](DEVELOPMENT.md) - Development workflow and conventions
- [advisory_pipeline/README.md](advisory_pipeline/README.md) - Technical reference
- [Tests README](advisory_pipeline/tests/README.md) - Testing guide

### For Agents
- [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) - Phase completion status
- Component READMEs in each module directory

### Architecture & Design
- [docs/PROTOTYPE_IMPLEMENTATION_PLAN.md](docs/PROTOTYPE_IMPLEMENTATION_PLAN.md) - Original plan
- [docs/Raw Design.md](docs/Raw Design.md) - Design discussions

## Configuration

Pipeline behavior is controlled via [advisory_pipeline/config.yaml](advisory_pipeline/config.yaml):

- **Data Sources**: File paths and API configurations
- **Rules**: Priority-ordered decision rules
- **States**: Final vs non-final state classification
- **Explanation Templates**: Human-readable text patterns

## Known Limitations

1. **Mock Data**: NVD and OSV use static fixtures (not real API calls)
2. **Single Environment**: No dev/staging/prod config separation
3. **Full Refresh**: No incremental processing yet
4. **Sequential Processing**: No parallelization of source fetching

See [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) for technical debt tracking.

## Contributing

This is a technical assessment prototype. For production deployment:

1. Replace mock NVD/OSV adapters with real API clients
2. Add authentication and rate limiting
3. Implement incremental processing
4. Add retry logic and circuit breakers
5. Deploy to production scheduler (Airflow, etc.)

## License

Internal prototype for Echo Data Engineering assessment.

---

**Status**: ✅ All 9 development phases complete
**Last Updated**: 2026-01-12
**Test Status**: 67 tests passing
