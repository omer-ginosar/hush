# Ingestion Layer

Source adapters for the CVE Advisory Pipeline.

## Overview

The ingestion layer provides a unified interface for fetching and normalizing data from multiple vulnerability sources:

- **Echo data.json**: Base advisory corpus (40K+ advisories)
- **Echo CSV**: Internal analyst overrides (1.9K+ entries)
- **NVD**: National Vulnerability Database (mock)
- **OSV**: Open Source Vulnerabilities (mock)

All adapters implement a common interface and produce normalized `SourceObservation` objects.

## Quick Start

```python
import yaml
from ingestion import EchoDataAdapter, EchoCsvAdapter, NvdAdapter, OsvAdapter

# Load configuration
with open('../config.yaml') as f:
    config = yaml.safe_load(f)

# Initialize adapters
echo_data = EchoDataAdapter(config['sources']['echo_data'])
echo_csv = EchoCsvAdapter(config['sources']['echo_csv'])
nvd = NvdAdapter(config['sources']['nvd'])
osv = OsvAdapter(config['sources']['osv'])

# Fetch observations
observations = []
observations.extend(echo_data.fetch())
observations.extend(echo_csv.fetch())
observations.extend(nvd.fetch())
observations.extend(osv.fetch())

print(f"Total observations: {len(observations)}")

# Check health
for adapter in [echo_data, echo_csv, nvd, osv]:
    health = adapter.get_health()
    print(f"{health.source_id}: {health.records_fetched} records, healthy={health.is_healthy}")
```

## Architecture

### Base Adapter

All adapters inherit from `BaseAdapter` and must implement:

- `fetch()`: Fetch and return normalized observations
- `normalize()`: Transform raw record to `SourceObservation`

### Data Model

**SourceObservation**: Unified data model with:
- Core identifiers (observation_id, source_id, cve_id, package_name)
- Temporal metadata (observed_at, source_updated_at)
- Raw payload preservation
- Normalized signals (fix_available, cvss_score, status, etc.)

**SourceHealth**: Health status with:
- is_healthy, last_fetch, records_fetched, error_message

## Adapters

### EchoDataAdapter

Parses Echo's `data.json` structure:
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
- Loads from local cache or URL
- Validates CVE ID format
- 40,189 observations processed

### EchoCsvAdapter

Parses analyst override CSV:
```csv
cve_id,package,status,fixed_version,internal_status
CVE-2022-23491,python-certifi,not_applicable,2022.9.24-1,code_not_in_use
```

**Features**:
- Content hash tracking for change detection
- UTF-8 encoding support
- 1,964 observations processed

### NvdAdapter

Simulates NVD API with mock responses.

**Features**:
- Extracts CVSS v3.1 scores and vectors
- Detects rejected CVEs
- Package-agnostic (CVE-level only)

### OsvAdapter

Simulates OSV API with mock responses.

**Features**:
- Maps OSV IDs to CVE IDs via aliases
- Extracts fixed versions from range events
- Handles multiple affected packages per vulnerability

## Testing

Run validation tests:
```bash
cd advisory_pipeline
python3 tests/test_adapters.py
```

Expected output:
```
✓ EchoDataAdapter: Loaded 40,189 observations
✓ EchoCsvAdapter: Loaded 1,964 observations
✓ NvdAdapter: Loaded 3 observations
✓ OsvAdapter: Loaded 3 observations

✅ All tests passed!
```

## Configuration

Adapters are configured via `config.yaml`:

```yaml
sources:
  echo_data:
    type: "json"
    cache_path: "../data.json"
    url: null  # Optional remote URL

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

## Production Considerations

### Mock to Real APIs

To replace mock adapters with real API calls:

1. Update `fetch()` method in `nvd_adapter.py` / `osv_adapter.py`
2. Add API authentication (keys, tokens)
3. Implement rate limiting and retry logic
4. Add HTTP caching
5. Keep `normalize()` method unchanged

### Error Handling

Current strategy: Fail-safe (errors captured in health status).

For production:
- Add exponential backoff retry
- Implement circuit breakers
- Add structured error types
- Log errors to external monitoring

### Performance

Current performance (single-threaded):
- Echo data: ~1s for 40K observations
- Total: ~2s for all sources

For production:
- Use `asyncio` for parallel fetching
- Add connection pooling
- Implement incremental updates

## API Reference

See [base_adapter.py](base_adapter.py) for complete interface documentation.

## License

Part of Echo's CVE Advisory Pipeline prototype.
