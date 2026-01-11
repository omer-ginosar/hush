# Phase 3: Storage Layer - Implementation Summary

## Overview

Phase 3 implements the storage layer for the CVE Advisory Pipeline using DuckDB. This layer provides data persistence for raw source observations and creates the foundation for dbt transformations in Phase 4.

**Key Architectural Decision:** State history tracking uses dbt snapshots (Phase 4) rather than Python-managed SCD2. This follows the standard dbt pattern and maintains clean separation of concerns.

## Components Delivered

### 1. Database (`storage/database.py`)

**Purpose:** Database connection management and schema initialization

**Key Features:**
- DuckDB connection lifecycle management
- Schema creation for raw landing zone tables
- Advisory state history table (populated by dbt snapshots in Phase 4)
- Pipeline run metadata tracking
- Indexed for query performance

**Tables Created:**
- `raw_echo_advisories`: Base advisory corpus from Echo data.json
- `raw_echo_csv`: Internal analyst overrides
- `raw_nvd_observations`: NVD CVE data
- `raw_osv_observations`: OSV vulnerability data
- `advisory_state_history`: SCD Type 2 state tracking (for dbt snapshots)
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
- advisory_state_history table created for dbt, not populated by Python

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

## Testing

Comprehensive test suite in `tests/test_storage.py`:

**Tests Cover:**
- Database schema initialization
- Run ID generation format
- Source observation loading
- Loader idempotency
- Multi-source batch loading

**Run Tests:**
```bash
cd advisory_pipeline
python3 -m pytest tests/test_storage.py -v
```

**Test Results:** All 5 tests passing

## Integration Points

### With Phase 2 (Ingestion Layer)
- Consumes `SourceObservation` objects from adapters
- Maps normalized observations to raw table schemas
- Preserves raw payloads for auditability

### With Phase 4 (dbt Layer)
- Raw tables serve as dbt sources
- dbt reads from raw_* tables for transformations
- dbt snapshots populate advisory_state_history
- Python only handles ingestion, dbt handles all transformations

## Architectural Decision: Why No Python SCD2?

**The Question:** Why not use Python to manage SCD Type 2 state history?

**The Answer:** dbt snapshots are the standard pattern for this:

### dbt-Native Approach (Implemented)
```
Ingestion → Raw Tables → dbt Transformations → dbt Snapshots → Output
```

**Advantages:**
- ✅ Standard dbt pattern
- ✅ Clean separation of concerns (Python = ingestion, dbt = transformation)
- ✅ Simpler codebase
- ✅ SQL-native temporal logic
- ✅ Easier to maintain and extend

### Python-Managed Alternative (Not Implemented)
```
Ingestion → Raw Tables → dbt → Python Decisioning → Python SCD2 → Output
```

**Why we didn't choose this:**
- ❌ Duplicates dbt functionality
- ❌ Mixes concerns (Python doing transformation)
- ❌ More complex
- ❌ Non-standard pattern

**Conclusion:** For a production-quality prototype, the dbt-native approach demonstrates better architectural understanding.

## Known Limitations

1. **Partial Indexes:** DuckDB doesn't support partial indexes (WHERE clause), so the `is_current` index includes all rows

2. **Batch Inserts:** Current implementation uses single-record inserts for simplicity. Could optimize with batch inserts for large datasets

3. **Reserved Keywords:** Column name `references` must be quoted in SQL due to being a DuckDB reserved keyword

## File Structure

```
advisory_pipeline/storage/
├── __init__.py          # Clean public exports
├── database.py          # Schema and connection management (217 lines)
└── loader.py            # Source observation loading (198 lines)
```

**Removed Components:**
- ~~scd2_manager.py~~ - Replaced by dbt snapshots in Phase 4

## Dependencies

- `duckdb>=0.9.0`: Database engine
- Standard library: `json`, `datetime`, `hashlib`, `typing`

## Design Philosophy

**Simplicity over Complexity:**
- Clear separation of concerns
- Python for ingestion, dbt for transformation
- Standard patterns over custom solutions
- No unnecessary abstractions

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
2. **dbt Snapshots:** Populate advisory_state_history with temporal tracking
3. **Marts:** Generate enriched advisory outputs for consumption

## Contact Points for Future Development

**If you need to:**
- Add new source types → Update Database (add raw table), Loader (add load method)
- Query raw data → Use Database.connect() and standard SQL
- Track state changes → Use dbt snapshots in Phase 4

**Critical Interfaces:**
- `SourceObservation` (from Phase 2)
- Raw table schemas (for Phase 4 dbt sources)
- advisory_state_history schema (for dbt snapshots)
