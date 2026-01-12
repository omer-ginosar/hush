# Ingestion Layer

Source adapters for the CVE Advisory Pipeline.

## Overview

The ingestion layer provides a unified interface for fetching and normalizing data from multiple vulnerability sources:

- **Echo data.json**: Base advisory corpus (40K+ advisories)
- **Echo CSV**: Internal analyst overrides (1.9K+ entries)
- **NVD**: National Vulnerability Database (live API with optional mock)
- **OSV**: Open Source Vulnerabilities (live data dump with optional mock)

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

### Adapter Runtime Features

- Rate limiting (token bucket per source)
- Retry with exponential backoff + jitter on 429/5xx/timeouts
- Circuit breaker (opens after repeated failures)
- In-run request caching (dedupes identical fetches)

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

Fetches from the NVD 2.0 API with rate limiting, retries, and circuit breaking.
Optional mock mode for tests and demos.

**Features**:
- Extracts CVSS v3.1/v3.0/v2 scores and vectors
- Detects rejected/disputed CVEs
- Honors `lastModStartDate`/`lastModEndDate` or `days_back`
- Package-agnostic (CVE-level only)

### OsvAdapter

Loads OSV vulnerabilities from the public data dump (zip) with local caching.
Optional mock mode for tests and demos.

**Features**:
- Maps OSV IDs to CVE IDs via aliases
- Extracts fixed versions from range events
- Handles multiple affected packages per vulnerability
- Filters by ecosystem and modified date window (optional)

## Testing

Run validation tests:
```bash
cd advisory_pipeline
python3 tests/test_adapters.py
```

Expected output (mock mode):
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
    cache_path: "../data/data.json"
    url: null  # Optional remote URL

  echo_csv:
    type: "csv"
    path: "../data/advisory-not-applicable.csv"

  nvd:
    type: "api"
    base_url: "https://services.nvd.nist.gov/rest/json/cves/2.0"
    api_key_env: "NVD_API_KEY"
    days_back: 30
    results_per_page: 2000
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
```

## Production Considerations

### Live Source Notes

- **NVD** requires an API key (`NVD_API_KEY`) for higher rate limits.
- **OSV** downloads the public data dump and caches it locally.
- Set `use_mock: true` for offline tests or demos.

### Error Handling

Current strategy: Fail-safe (errors captured in health status).

For production:
- Add structured error types
- Log errors to external monitoring

### Performance

For production:
- Use `asyncio` for parallel fetching
- Add connection pooling
- Implement incremental updates
- Use ecosystem filters and max record limits for OSV

## API Reference

See [base_adapter.py](base_adapter.py) for complete interface documentation.

## License

Part of Echo's CVE Advisory Pipeline prototype.
