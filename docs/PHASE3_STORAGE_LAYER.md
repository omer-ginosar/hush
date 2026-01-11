# Phase 3: Storage Layer - Implementation Summary

## Overview

Phase 3 implements the storage layer for the CVE Advisory Pipeline using DuckDB with SCD Type 2 (Slowly Changing Dimension) history tracking. This layer provides data persistence, state management, and temporal query capabilities.

## Components Delivered

### 1. Database (`storage/database.py`)

**Purpose:** Database connection management and schema initialization

**Key Features:**
- DuckDB connection lifecycle management
- Schema creation for raw landing zone tables
- SCD Type 2 state history table
- Pipeline run metadata tracking
- Indexed for query performance

**Tables Created:**
- `raw_echo_advisories`: Base advisory corpus from Echo data.json
- `raw_echo_csv`: Internal analyst overrides
- `raw_nvd_observations`: NVD CVE data
- `raw_osv_observations`: OSV vulnerability data
- `advisory_state_history`: SCD Type 2 state tracking
- `pipeline_runs`: Pipeline execution metadata

**Usage:**
```python
from storage import Database

db = Database("advisory_pipeline.duckdb")
db.initialize_schema()
run_id = db.get_current_run_id()
```

**Design Decisions:**
- DuckDB instead of SQLite for better dbt compatibility
- JSON columns for complex payloads and evidence
- Quoted "references" column name (DuckDB reserved keyword)
- Standard indexes (no partial indexes due to DuckDB limitations)

### 2. Source Loader (`storage/loader.py`)

**Purpose:** Load normalized observations from adapters into raw tables

**Key Features:**
- Per-source loader methods with explicit field mapping
- DELETE + INSERT pattern for idempotent loads
- JSON serialization for complex fields
- Batch loading support via `load_all()` method

**Usage:**
```python
from storage import SourceLoader

loader = SourceLoader(db)
count = loader.load_echo_advisories(observations, run_id)
# Or load all sources at once
counts = loader.load_all(echo_obs, csv_obs, nvd_obs, osv_obs, run_id)
```

**Design Decisions:**
- Separate methods per source for clarity
- Idempotent loads via run_id-based deletion
- Returns count of loaded records for observability

### 3. SCD2 Manager (`storage/scd2_manager.py`)

**Purpose:** Manage advisory state history with temporal tracking

**Key Features:**
- State change detection
- Automatic history record management
- Point-in-time queries
- Full change history retrieval

**Key Operations:**
- `get_current_state()`: Get active state for an advisory
- `has_state_changed()`: Detect meaningful changes
- `apply_state()`: Write new state, manage SCD2 history
- `get_state_at_time()`: Query historical state
- `get_history()`: Full change history

**Usage:**
```python
from storage import SCD2Manager, AdvisoryState

scd2 = SCD2Manager(db)

state = AdvisoryState(
    advisory_id="pkg:CVE-2024-0001",
    cve_id="CVE-2024-0001",
    package_name="pkg",
    state="fixed",
    state_type="final",
    fixed_version="1.2.3",
    confidence="high",
    explanation="Fixed in version 1.2.3",
    reason_code="UPSTREAM_FIX",
    evidence={"fixed_version": "1.2.3"},
    decision_rule="R2:upstream_fix",
    contributing_sources=["osv"],
    dissenting_sources=[],
    staleness_score=0.0
)

changed = scd2.apply_state(state, run_id)
```

**SCD Type 2 Pattern:**
- Each state change creates a new record
- Previous record is closed with `effective_to` timestamp
- `is_current=TRUE` flag marks active state
- Only one current record per advisory
- Enables point-in-time queries and audit trails

**Change Detection:**
Changes that trigger new history record:
- State change (e.g., pending_upstream → fixed)
- Fixed version change
- Confidence level change
- Reason code change

## Testing

Comprehensive test suite in `tests/test_storage.py`:

**Tests Cover:**
- Database schema initialization
- Run ID generation format
- Source observation loading
- Loader idempotency
- SCD2 first state creation
- SCD2 state transitions
- SCD2 skip unchanged states
- Point-in-time queries

**Run Tests:**
```bash
cd advisory_pipeline
python3 -m pytest tests/test_storage.py -v
```

**Test Results:** All 8 tests passing

## Integration Points

### With Phase 2 (Ingestion Layer)
- Consumes `SourceObservation` objects from adapters
- Maps normalized observations to raw table schemas
- Preserves raw payloads for auditability

### With Phase 4 (dbt Layer) - Future
- Raw tables serve as dbt sources
- dbt reads from raw_* tables
- dbt can read advisory_state_history
- Python writes state changes, dbt generates decisions

### With Phase 5 (Decisioning) - Future
- Decisioning produces `AdvisoryState` objects
- SCD2Manager persists state with history
- Enables temporal queries for analysis

## Known Limitations

1. **Partial Indexes:** DuckDB doesn't support partial indexes (WHERE clause), so the `is_current` index includes all rows rather than only current ones

2. **Batch Inserts:** Current implementation uses single-record inserts for simplicity. Could be optimized with batch inserts for large datasets

3. **Reserved Keywords:** Column name `references` must be quoted in SQL due to being a DuckDB reserved keyword

4. **In-Memory Mode:** DuckDB supports in-memory mode (`:memory:`), but not used in tests to avoid serialization issues

## File Structure

```
advisory_pipeline/storage/
├── __init__.py          # Clean public exports
├── database.py          # Schema and connection management (217 lines)
├── loader.py            # Source observation loading (198 lines)
└── scd2_manager.py      # SCD Type 2 state management (271 lines)
```

## Dependencies

- `duckdb>=0.9.0`: Database engine
- Standard library: `json`, `datetime`, `hashlib`, `typing`, `dataclasses`

## Design Philosophy

**Simplicity over Complexity:**
- Clear separation of concerns
- Explicit over implicit
- No unnecessary abstractions
- Idiomatic Python

**Production Quality:**
- Comprehensive docstrings
- Type hints throughout
- Error-safe operations
- Test coverage

**Maintainability:**
- Small, focused functions
- Explicit field mapping
- Clear naming conventions
- Minimal dependencies

## Next Steps

Phase 3 provides the storage foundation. Future phases will:

1. **Phase 4 (dbt):** Build transformation layer on these raw tables
2. **Phase 5 (Decisioning):** Generate AdvisoryState objects to persist
3. **Integration:** Connect ingestion → storage → decisioning → output

## Contact Points for Future Development

**If you need to:**
- Add new source types → Update Database (add raw table), Loader (add load method)
- Change state fields → Update AdvisoryState dataclass, Database schema
- Add state change rules → Update has_state_changed() logic
- Query historical states → Use get_state_at_time() or get_history()

**Critical Interfaces:**
- `SourceObservation` (from Phase 2)
- `AdvisoryState` (for Phase 5)
- Raw table schemas (for Phase 4 dbt)
