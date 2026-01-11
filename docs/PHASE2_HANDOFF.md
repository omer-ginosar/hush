# Phase 2 Handoff Document: Ingestion Layer

**Phase**: Phase 2 - Ingestion Layer
**Status**: ✅ COMPLETE
**Date**: 2026-01-11
**Branch**: `feature/phase2-ingestion-layer`

---

## Executive Summary

Phase 2 implements the ingestion layer for the CVE Advisory Pipeline. All source adapters have been implemented with production-quality code, validated against real data, and documented for handoff to subsequent phases.

**What Was Built**: Four fully functional adapters (Echo data.json, Echo CSV, NVD mock, OSV mock) with unified data model and health monitoring.
**What's Next**: Implement storage layer to persist observations in DuckDB with SCD Type 2 history tracking.

---

## Deliverables

### 1. Base Adapter Framework

**File**: `advisory_pipeline/ingestion/base_adapter.py`

**Key Components**:
- `SourceObservation` dataclass: Unified data model for all sources
- `SourceHealth` dataclass: Adapter health status tracking
- `BaseAdapter` abstract class: Common interface all adapters implement

**Design Principles**:
- **Separation of Concerns**: Adapters handle fetching; normalization is separate
- **Fail-Safe**: Errors are captured in health status, not thrown
- **Minimal**: No unnecessary abstractions or features

**Code Statistics**:
- Lines: 97
- Dependencies: Standard library only (abc, dataclasses, datetime, typing)

### 2. Echo Data Adapter

**File**: `advisory_pipeline/ingestion/echo_data_adapter.py`

**Purpose**: Parses Echo's data.json (the base advisory corpus)

**Data Schema Handled**:
```json
{
  "package-name": {
    "CVE-YYYY-NNNNN": {
      "fixed_version": "1.2.3-1"
    }
  }
}
```

**Features**:
- Loads from local cache (primary) or URL (fallback)
- Validates CVE ID format
- Generates stable observation IDs using MD5 hash
- Handles empty CVE entries gracefully

**Performance**:
- Successfully processes 40,189 observations from data.json
- Average processing time: <1 second

**Code Statistics**:
- Lines: 129
- Dependencies: hashlib, json, datetime, pathlib, requests

### 3. Echo CSV Adapter

**File**: `advisory_pipeline/ingestion/echo_csv_adapter.py`

**Purpose**: Parses Echo's internal analyst override CSV

**CSV Schema Handled**:
```csv
cve_id,package,status,fixed_version,internal_status
CVE-2022-23491,python-certifi,not_applicable,2022.9.24-1,code_not_in_use
```

**Features**:
- Validates CVE ID and package name
- Content hash tracking for change detection
- Handles missing CSV gracefully (returns empty list)
- UTF-8 encoding support

**Performance**:
- Successfully processes 1,964 observations from advisory_not_applicable.csv
- Average processing time: <100ms

**Code Statistics**:
- Lines: 120
- Dependencies: csv, hashlib, datetime, pathlib

### 4. NVD Mock Adapter

**File**: `advisory_pipeline/ingestion/nvd_adapter.py`

**Purpose**: Simulates NVD API with realistic mock responses

**Mock Schema**: Matches real NVD API 2.0 structure
```json
{
  "vulnerabilities": [{
    "cve": {
      "id": "CVE-2024-0001",
      "vulnStatus": "Analyzed",
      "metrics": { "cvssMetricV31": [...] },
      "references": [...]
    }
  }]
}
```

**Features**:
- Extracts CVSS v3.1 scores and vectors
- Detects rejected CVEs
- Extracts references and descriptions
- NVD is CVE-centric (no package-level data)

**Mock Data**: 3 test vulnerabilities (1 analyzed, 1 rejected, 1 critical)

**Code Statistics**:
- Lines: 127
- Dependencies: hashlib, json, datetime, pathlib

### 5. OSV Mock Adapter

**File**: `advisory_pipeline/ingestion/osv_adapter.py`

**Purpose**: Simulates OSV API with realistic mock responses

**Mock Schema**: Matches real OSV API structure
```json
{
  "vulns": [{
    "id": "GHSA-xxxx-xxxx-xxxx",
    "aliases": ["CVE-2024-1234"],
    "affected": [{
      "package": {"name": "pkg", "ecosystem": "PyPI"},
      "ranges": [{"events": [{"fixed": "1.2.3"}]}]
    }]
  }]
}
```

**Features**:
- Maps OSV IDs to CVE IDs via aliases
- Extracts fixed versions from range events
- Supports multiple affected packages per vulnerability
- Identifies fix commit URLs

**Mock Data**: 3 test vulnerabilities with different fix statuses

**Code Statistics**:
- Lines: 145
- Dependencies: hashlib, json, datetime, pathlib

### 6. Mock Response Fixtures

**Files**:
- `advisory_pipeline/ingestion/mock_responses/nvd_responses.json`
- `advisory_pipeline/ingestion/mock_responses/osv_responses.json`

**Purpose**: Realistic test data matching real API schemas

**Coverage**:
- Analyzed CVEs with CVSS scores
- Rejected CVEs
- Fixed vulnerabilities with version info
- Unfixed vulnerabilities

### 7. Validation Tests

**File**: `advisory_pipeline/tests/test_adapters.py`

**Test Coverage**:
- ✓ Echo data adapter can load and normalize data.json
- ✓ Echo CSV adapter can load and normalize CSV overrides
- ✓ NVD adapter can load and normalize mock responses
- ✓ OSV adapter can load and normalize mock responses
- ✓ Health checks work for all adapters
- ✓ Observation structure validation

**Test Results**:
```
✓ EchoDataAdapter: Loaded 40,189 observations
✓ EchoCsvAdapter: Loaded 1,964 observations
✓ NvdAdapter: Loaded 3 observations
✓ OsvAdapter: Loaded 3 observations

✅ All tests passed!
```

**Running Tests**:
```bash
cd advisory_pipeline
pip install -r requirements.txt
python3 tests/test_adapters.py
```

---

## Design Decisions & Rationale

### 1. Abstract Base Class Pattern

**Decision**: Use ABC with abstract methods for adapter interface.

**Rationale**:
- **Type Safety**: Forces all adapters to implement required methods
- **Documentation**: Interface is self-documenting via abstract methods
- **Maintainability**: Future adapters know exactly what to implement
- **IDE Support**: Better autocomplete and type checking

**Trade-off**: Slightly more boilerplate, but worth it for clarity.

### 2. Unified SourceObservation Model

**Decision**: Single dataclass for all sources with optional fields.

**Rationale**:
- **Simplicity**: One type to handle, not N source-specific types
- **Flexibility**: Optional fields handle heterogeneous data
- **Composability**: Easy to pass between pipeline stages
- **Future-Proof**: New sources just add observations to the same pool

**Trade-off**: Some fields always None for certain sources (acceptable).

### 3. Stable Observation IDs

**Decision**: Generate deterministic IDs using MD5(source:package:cve).

**Rationale**:
- **Idempotency**: Re-running pipeline produces same IDs
- **Deduplication**: Easy to detect duplicate observations
- **Debugging**: IDs are reproducible for investigation
- **SCD2 Support**: Stable IDs enable state change detection

**Trade-off**: MD5 truncated to 16 chars (collision risk negligible for this scale).

### 4. Mock vs Real APIs

**Decision**: Use static mock responses for NVD and OSV in prototype.

**Rationale**:
- **Deterministic Testing**: Same results every run
- **No API Keys**: Can run without credentials
- **Offline Development**: No network dependency
- **Speed**: No API rate limits or latency

**Trade-off**: Not testing real API integration (acceptable for prototype).

**Production Path**: Replace `fetch()` implementation with real API calls; `normalize()` logic stays the same.

### 5. Error Handling Strategy

**Decision**: Capture errors in health status, return empty list on failure.

**Rationale**:
- **Graceful Degradation**: One source failure doesn't crash pipeline
- **Observability**: Health checks expose what's broken
- **Resilience**: Pipeline can run with partial data
- **Simplicity**: No complex retry logic in prototype

**Trade-off**: Silent failures (mitigated by health monitoring).

---

## Interface Contracts

### SourceObservation Schema

This is the canonical output format all adapters produce:

```python
@dataclass
class SourceObservation:
    # Core identifiers
    observation_id: str           # Stable, deterministic ID
    source_id: str                # "echo_data" | "echo_csv" | "nvd" | "osv"
    cve_id: Optional[str]         # "CVE-YYYY-NNNNN" or None
    package_name: Optional[str]   # Package identifier or None

    # Temporal metadata
    observed_at: datetime         # When this was fetched
    source_updated_at: Optional[datetime]  # When source says it was updated

    # Raw data preservation
    raw_payload: Dict[str, Any]   # Original source response

    # Normalized signals (all optional)
    fix_available: Optional[bool]
    fixed_version: Optional[str]
    affected_versions: Optional[str]
    status: Optional[str]         # "fixed" | "affected" | "not_applicable"
    rejection_status: Optional[str]  # "none" | "rejected" | "disputed"
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    exploit_available: Optional[bool]
    references: Optional[List[str]]
    notes: Optional[str]
```

### Adapter Interface

All adapters must implement:

```python
class BaseAdapter(ABC):
    def __init__(self, config: Dict[str, Any]):
        # Initialize with config from config.yaml

    @abstractmethod
    def fetch(self) -> List[SourceObservation]:
        # Fetch and return normalized observations

    @abstractmethod
    def normalize(self, raw_record: Dict[str, Any], **kwargs) -> Optional[SourceObservation]:
        # Transform raw record to SourceObservation

    def get_health(self) -> SourceHealth:
        # Return health status
```

### Configuration Contract

Adapters expect config like this:

```yaml
sources:
  echo_data:
    type: "json"
    cache_path: "../data.json"
    url: null  # Optional

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

---

## Usage Examples

### Loading All Sources

```python
import yaml
from ingestion import EchoDataAdapter, EchoCsvAdapter, NvdAdapter, OsvAdapter

# Load config
with open('config.yaml') as f:
    config = yaml.safe_load(f)

# Initialize adapters
echo_data = EchoDataAdapter(config['sources']['echo_data'])
echo_csv = EchoCsvAdapter(config['sources']['echo_csv'])
nvd = NvdAdapter(config['sources']['nvd'])
osv = OsvAdapter(config['sources']['osv'])

# Fetch observations
all_observations = []
all_observations.extend(echo_data.fetch())
all_observations.extend(echo_csv.fetch())
all_observations.extend(nvd.fetch())
all_observations.extend(osv.fetch())

print(f"Total observations: {len(all_observations)}")
```

### Health Monitoring

```python
# Check adapter health
for adapter in [echo_data, echo_csv, nvd, osv]:
    health = adapter.get_health()
    status = "✓" if health.is_healthy else "✗"
    print(f"{status} {health.source_id}: {health.records_fetched} records")
    if not health.is_healthy:
        print(f"  Error: {health.error_message}")
```

### Change Detection (CSV)

```python
# Detect CSV changes
csv_adapter = EchoCsvAdapter(config['sources']['echo_csv'])

# First fetch
csv_adapter.fetch()
print(f"Changed: {csv_adapter.has_changed()}")  # True (first time)

# Second fetch (no changes)
csv_adapter.fetch()
print(f"Changed: {csv_adapter.has_changed()}")  # False

# After CSV modified
# csv_adapter.fetch()
# print(f"Changed: {csv_adapter.has_changed()}")  # True
```

---

## Next Phase: Phase 3 - Storage Layer

### Scope

Implement database layer to persist observations and manage SCD Type 2 history.

### Components to Build

| File | Purpose | Dependencies |
|------|---------|--------------|
| `storage/database.py` | DuckDB initialization & schema | Phase 2: None |
| `storage/loader.py` | Load observations to raw tables | Phase 2: `SourceObservation` |
| `storage/scd2_manager.py` | State history management | Phase 2: None (uses DB directly) |

### Interface Contract for Phase 3

**Input**: `List[SourceObservation]` from Phase 2 adapters

**Output**:
- Raw tables in DuckDB (`raw_echo_advisories`, `raw_echo_csv`, `raw_nvd_observations`, `raw_osv_observations`)
- SCD Type 2 table (`advisory_state_history`)
- Run metadata (`pipeline_runs`)

**Key Operations**:
```python
from storage import Database, SourceLoader

db = Database("advisory_pipeline.duckdb")
db.initialize_schema()

loader = SourceLoader(db)
loader.load_echo_advisories(observations, run_id)
```

### Success Criteria

- [ ] DuckDB database created with proper schema
- [ ] All raw tables populated from observations
- [ ] SCD2 table structure matches dbt expectations
- [ ] Point-in-time queries work correctly
- [ ] State change detection logic implemented

### Reference

See [PROTOTYPE_IMPLEMENTATION_PLAN.md](PROTOTYPE_IMPLEMENTATION_PLAN.md) lines 852-1289 for detailed storage layer implementation guidance.

---

## Known Limitations

1. **Mock Data Only**: NVD and OSV use static responses
   - **Impact**: Can't test real API behavior, rate limits, auth
   - **Mitigation**: Mock schemas match real APIs exactly
   - **Follow-up**: Replace `fetch()` with real API calls in production

2. **No Retry Logic**: Adapters fail immediately on error
   - **Impact**: Transient network issues cause failures
   - **Mitigation**: Health checks expose failures
   - **Follow-up**: Add exponential backoff retry in production

3. **No Caching for APIs**: Mock adapters don't cache
   - **Impact**: N/A for prototype (no real API calls)
   - **Follow-up**: Add HTTP caching when using real APIs

4. **Basic Error Messages**: Errors captured as strings
   - **Impact**: Limited debugging info
   - **Mitigation**: Raw payloads preserved for inspection
   - **Follow-up**: Add structured error types with context

5. **No Async Processing**: Adapters run synchronously
   - **Impact**: Sources fetched sequentially (slower)
   - **Mitigation**: Fast enough for prototype (<2 seconds total)
   - **Follow-up**: Use asyncio for parallel fetching in production

---

## Testing Checklist

✅ All adapters implement `BaseAdapter` interface
✅ All adapters produce valid `SourceObservation` objects
✅ Echo data adapter loads 40K+ observations from data.json
✅ Echo CSV adapter loads 1,964 observations from CSV
✅ NVD adapter loads mock responses correctly
✅ OSV adapter loads mock responses correctly
✅ Health checks return correct status
✅ Error handling works (tested with missing files)
✅ CVE ID validation works
✅ Observation IDs are deterministic
✅ Package `__init__.py` exports all public APIs
✅ Tests pass on actual data files

---

## Verification Commands

```bash
# Run validation tests
cd advisory_pipeline
python3 tests/test_adapters.py

# Check imports work
python3 -c "from ingestion import EchoDataAdapter; print('✓ Import OK')"

# Verify data files exist
test -f ../data.json && echo "✓ data.json exists"
test -f ../advisory_not_applicable.csv && echo "✓ CSV exists"

# Verify mock files exist
test -f ingestion/mock_responses/nvd_responses.json && echo "✓ NVD mock exists"
test -f ingestion/mock_responses/osv_responses.json && echo "✓ OSV mock exists"

# Count observations
python3 -c "
import yaml
from ingestion import EchoDataAdapter
with open('config.yaml') as f:
    cfg = yaml.safe_load(f)
adapter = EchoDataAdapter(cfg['sources']['echo_data'])
print(f'✓ Observations: {len(adapter.fetch())}')
"
```

---

## Git Information

**Branch**: `feature/phase2-ingestion-layer`
**Commit**: [To be filled after commit]

**Files Changed**:
```
 advisory_pipeline/ingestion/__init__.py                     |  24 +++
 advisory_pipeline/ingestion/base_adapter.py                 |  97 +++++++++++
 advisory_pipeline/ingestion/echo_csv_adapter.py             | 120 +++++++++++++
 advisory_pipeline/ingestion/echo_data_adapter.py            | 129 ++++++++++++++
 advisory_pipeline/ingestion/mock_responses/nvd_responses.json |  69 ++++++++
 advisory_pipeline/ingestion/mock_responses/osv_responses.json |  67 ++++++++
 advisory_pipeline/ingestion/nvd_adapter.py                  | 127 +++++++++++++
 advisory_pipeline/ingestion/osv_adapter.py                  | 145 +++++++++++++++
 advisory_pipeline/tests/test_adapters.py                    | 141 ++++++++++++++
 docs/IMPLEMENTATION_STATUS.md                               |  35 +++-
 docs/PHASE2_HANDOFF.md                                      | 610 +++++++
 11 files changed, 1,563 insertions(+)
```

---

## Questions for Review

1. **API Integration**: Should we implement real NVD/OSV API calls now or wait for production?

2. **Error Handling**: Is current fail-safe approach (capture errors, return empty) acceptable, or should we fail-fast?

3. **Performance**: 40K observations in <1s is acceptable for prototype. Any concerns for production scale?

4. **Data Quality**: Should we add more validation (e.g., CVSS score ranges, version format checks) or keep it minimal?

5. **Extensibility**: If new sources are added (e.g., GitHub Security Advisories), is the `SourceObservation` model flexible enough?

---

## Sign-Off

**Phase 2 Status**: ✅ COMPLETE
**Ready for Phase 3**: ✅ YES
**Blockers**: None
**Risks**: None identified

**Approver**: _[To be filled by reviewer]_
**Date**: _[To be filled by reviewer]_

---

**Next Steps**:
1. Review this handoff document
2. Approve Phase 2 completion
3. Merge `feature/phase2-ingestion-layer` to main
4. Assign Phase 3 (Storage Layer) to implementation agent
5. Begin Phase 3 work on new branch `feature/phase3-storage-layer`

**End of Phase 2 Handoff Document**
