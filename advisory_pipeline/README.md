# CVE Advisory Pipeline - Phase 1: Project Setup

## Overview

This is the foundational setup for a production-like CVE advisory enrichment pipeline that:
- Ingests real advisory data (data.json) + simulated upstream sources (NVD, OSV)
- Applies a deterministic rule engine with full explainability
- Maintains SCD Type 2 state history in DuckDB
- Uses dbt for all data transformations
- Produces customer-facing outputs with explanations

**Current Phase**: Phase 1 - Project Setup
**Status**: ✓ Complete

## Project Structure

```
advisory_pipeline/
├── README.md                    # This file
├── requirements.txt             # Python dependencies
├── config.yaml                  # Pipeline configuration
├── run_pipeline.py              # Main orchestrator (Phase 2+)
├── demo.py                      # Multi-run demonstration (Phase 2+)
│
├── ingestion/                   # Source adapters (Phase 2)
│   ├── __init__.py
│   ├── base_adapter.py
│   ├── echo_data_adapter.py
│   ├── echo_csv_adapter.py
│   ├── nvd_adapter.py
│   ├── osv_adapter.py
│   └── mock_responses/
│       ├── nvd_responses.json
│       └── osv_responses.json
│
├── dbt_project/                 # dbt transformations (Phase 4)
│   ├── dbt_project.yml
│   ├── profiles.yml
│   ├── seeds/
│   ├── models/
│   │   ├── staging/
│   │   ├── intermediate/
│   │   └── marts/
│   ├── macros/
│   └── tests/
│
├── decisioning/                 # Rule engine (Phase 5)
│   ├── __init__.py
│   ├── rule_engine.py
│   ├── rules.py
│   ├── state_machine.py
│   └── explainer.py
│
├── storage/                     # Database management (Phase 3)
│   ├── __init__.py
│   ├── database.py
│   ├── scd2_manager.py
│   └── loader.py
│
├── observability/               # Metrics and quality (Phase 6)
│   ├── __init__.py
│   ├── metrics.py
│   ├── quality_checks.py
│   └── reporter.py
│
├── output/                      # Generated outputs
│   └── .gitkeep
│
└── tests/                       # Unit tests
    ├── test_rules.py
    ├── test_scd2.py
    └── test_conflict_resolution.py
```

## Setup Instructions

### Prerequisites

- Python 3.11 or higher
- Access to project root directory containing `data.json` and `advisory_not_applicable.csv`

### Installation

1. Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:

```bash
cd advisory_pipeline
pip install -r requirements.txt
```

### Configuration

The pipeline is configured via [config.yaml](config.yaml):

- **Database**: DuckDB location (defaults to `advisory_pipeline.duckdb`)
- **Sources**: Data source configurations
  - `echo_data`: Main advisory corpus (data.json)
  - `echo_csv`: Internal analyst overrides (advisory_not_applicable.csv)
  - `nvd`: Mock NVD API responses
  - `osv`: Mock OSV API responses
- **Rules**: Decision rule definitions with priority ordering
- **States**: Valid state classifications (final vs non-final)
- **Explanation Templates**: Human-readable explanation formats

## Phase 1 Deliverables

✓ Complete project directory structure
✓ Python package initialization
✓ Dependencies specification (requirements.txt)
✓ Pipeline configuration (config.yaml)
✓ Updated .gitignore for pipeline artifacts
✓ Project documentation (this README)

## How This Fits Into the Prototype

**Phase 1** establishes the foundation. Subsequent phases will:

- **Phase 2**: Implement ingestion adapters to load data from sources
- **Phase 3**: Build storage layer with DuckDB and SCD Type 2 management
- **Phase 4**: Create dbt models for data transformations
- **Phase 5**: Implement rule engine for advisory state decisions
- **Phase 6**: Add observability, metrics, and quality checks
- **Phase 7**: Build orchestration and demo scripts

## Design Decisions

### Why DuckDB over SQLite?

DuckDB provides better dbt integration and more powerful SQL capabilities while maintaining the lightweight, embedded nature needed for this prototype.

### Why dbt?

Separating transformation logic into dbt provides:
- SQL-based transformations (declarative, testable)
- Built-in testing and documentation
- Clear lineage and dependency management
- Industry-standard approach for data transformations

### Configuration Approach

Externalized configuration allows:
- Different environments (dev, test, prod)
- Easy source switching (mock vs real APIs)
- Rule modification without code changes
- Template-based explanations for maintainability

### Minimal Scope

Phase 1 intentionally includes only:
- Directory structure
- Configuration
- Documentation

No implementation code to avoid scope creep. Clean interfaces for subsequent phases.

## Known Limitations

- Configuration references paths relative to project root (assumes specific directory structure)
- No environment-specific config files yet (could add config.dev.yaml, config.prod.yaml)
- Mock data file paths hardcoded (could be made more flexible)

## Follow-Up Work

Next phases should:
1. Implement base adapter interface and concrete adapters (Phase 2)
2. Create database schema and SCD2 manager (Phase 3)
3. Build dbt project with staging, intermediate, and mart models (Phase 4)
4. Implement rule engine with explainability (Phase 5)

## Interface Assumptions

For subsequent phases:

**Inputs** (from project root):
- `data.json`: Echo advisory corpus
- `advisory_not_applicable.csv`: Analyst overrides

**Outputs** (to `output/`):
- `advisory_current.json`: Current state of all advisories
- `advisory_history.json`: Full state change history
- `run_report.json`: Pipeline execution metrics

**Shared State**:
- `advisory_pipeline.duckdb`: Central database for all pipeline data
