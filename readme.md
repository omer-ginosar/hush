# 🌑 Hush - CVE Advisory Pipeline

Home-assignment repo: a production-style CVE advisory enrichment pipeline built with Python, DuckDB, and dbt.

## 🌐 Overview

This pipeline ingests security advisories from multiple sources (Echo data, NVD, OSV), applies deterministic business rules, and produces enriched advisory states with full explainability and state-change history.

**Highlights**
- Multi-source ingestion with conflict resolution
- Deterministic rule-based decision engine
- SCD Type 2 state history tracking
- dbt-based transformations (staging → marts)
- Observability + quality checks on every run
- Explainable decisions with evidence

## 🧭 Quick Start

### Prerequisites
- Python 3.11+
- Input data files in `data/`:
  - `data/data.json` (Echo advisory corpus)
  - `data/advisory-not-applicable.csv` (analyst overrides)
  - `data/data-sample.json` (optional sample subset)

### Install
```bash
python3 -m venv venv
source venv/bin/activate
cd advisory_pipeline
pip install -r requirements.txt
```

### Run
```bash
# Single run
python3 run_pipeline.py

# Multi-run demonstration with visual CVE tracking
python3 demo.py
```

Optional NVD API key for higher rate limits:
```bash
export NVD_API_KEY="your-key"
```

### Outputs
- `output/advisory_current.json` - Current advisory states
- `output/run-report-*.md` - Execution metrics and quality checks
- `advisory_pipeline.duckdb` - Full state history database

## 🗺️ Architecture

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

**Components**
- **Ingestion**: Source adapters for Echo, NVD, OSV
- **Storage**: DuckDB schema + loading
- **dbt**: Staging → intermediate → marts
- **Decisioning**: Priority-ordered rule engine
- **Observability**: Metrics + quality checks

## ✅ Decision Engine (Summary)

| Priority | Rule | State | Trigger |
|----------|------|-------|---------|
| 0 | CSV Override | `not_applicable` | Internal analyst decision |
| 1 | NVD Rejected | `not_applicable` | CVE rejected by NVD |
| 2 | Upstream Fix | `fixed` | Fix version available |
| 5 | Under Investigation | `under_investigation` | New CVE, no signals |
| 6 | Pending Upstream | `pending_upstream` | Default fallback |

Each decision includes state, confidence, reason code, explanation, and evidence.

## 🧪 Testing

```bash
cd advisory_pipeline
python3 -m pytest tests/ -v
```

See [advisory_pipeline/tests/readme.md](advisory_pipeline/tests/readme.md) for details.

## 📁 Repo Layout

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

## 📚 Documentation Index

- [advisory_pipeline/demo.md](advisory_pipeline/demo.md) - Visual demo guide
- [advisory_pipeline/readme.md](advisory_pipeline/readme.md) - Technical reference
- [docs/implementation-status.md](docs/implementation-status.md) - Phase completion status
- [docs/prototype-implementation-plan.md](docs/prototype-implementation-plan.md) - Original plan
- [docs/raw-design.md](docs/raw-design.md) - Design discussions
- [docs/assets/](docs/assets) - Diagrams + source files
- [docs/phase-11/development.md](docs/phase-11/development.md) - Extension guide

## ⚠️ Known Limitations

1. OSV dump size: full data dump with local cache; use filters for scale
2. Single environment: no dev/staging/prod separation
3. Incremental processing: NVD uses time windows without persisted checkpoints
4. Sequential processing: source fetching is not parallelized

## 📌 Status

- **Phase completion**: ✅ All development phases complete
- **Last updated**: 2026-01-12
- **Test status**: 84 tests passing
