# CVE Advisory Pipeline Prototype - Implementation Plan

## Overview

Build a production-like CVE advisory enrichment pipeline that:
- Ingests real advisory data (data.json) + simulated upstream sources
- Applies a deterministic rule engine with full explainability
- Maintains SCD Type 2 state history in SQLite
- Uses dbt for all data transformations
- Produces customer-facing outputs with explanations

**Target runtime:** Python 3.11+ with dbt-duckdb (DuckDB as SQLite alternative for better dbt support)

---

## Project Structure

```
advisory_pipeline/
├── README.md
├── requirements.txt
├── config.yaml
├── run_pipeline.py              # Main orchestrator
├── demo.py                      # Multi-run demonstration
│
├── ingestion/
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
├── dbt_project/
│   ├── dbt_project.yml
│   ├── profiles.yml
│   ├── packages.yml
│   ├── seeds/
│   │   ├── package_aliases.csv
│   │   └── rule_definitions.csv
│   ├── models/
│   │   ├── sources.yml
│   │   ├── staging/
│   │   │   ├── stg_echo_advisories.sql
│   │   │   ├── stg_echo_csv.sql
│   │   │   ├── stg_nvd_observations.sql
│   │   │   ├── stg_osv_observations.sql
│   │   │   └── staging.yml
│   │   ├── intermediate/
│   │   │   ├── int_source_observations.sql
│   │   │   ├── int_enriched_advisories.sql
│   │   │   ├── int_decision_inputs.sql
│   │   │   └── intermediate.yml
│   │   └── marts/
│   │       ├── mart_advisory_decisions.sql
│   │       ├── mart_advisory_state_history.sql
│   │       ├── mart_advisory_current.sql
│   │       └── marts.yml
│   ├── macros/
│   │   ├── generate_explanation.sql
│   │   ├── resolve_conflict.sql
│   │   └── scd2_merge.sql
│   └── tests/
│       ├── assert_no_orphan_states.sql
│       └── assert_valid_transitions.sql
│
├── decisioning/
│   ├── __init__.py
│   ├── rule_engine.py
│   ├── rules.py
│   ├── state_machine.py
│   └── explainer.py
│
├── storage/
│   ├── __init__.py
│   ├── database.py
│   ├── scd2_manager.py
│   └── loader.py
│
├── observability/
│   ├── __init__.py
│   ├── metrics.py
│   ├── quality_checks.py
│   └── reporter.py
│
├── output/
│   └── .gitkeep
│
└── tests/
    ├── test_rules.py
    ├── test_scd2.py
    └── test_conflict_resolution.py
```

---

## Phase 1: Project Setup

### Step 1.1: Create requirements.txt

```
dbt-duckdb>=1.7.0
duckdb>=0.9.0
pyyaml>=6.0
requests>=2.31.0
jinja2>=3.1.0
pytest>=7.4.0
tabulate>=0.9.0
```

### Step 1.2: Create config.yaml

```yaml
pipeline:
  name: "echo_advisory_pipeline"
  version: "0.1.0"
  
database:
  path: "advisory_pipeline.duckdb"
  
sources:
  echo_data:
    type: "json"
    # If network available, fetch from real URL
    # Otherwise use cached file
    url: "https://example.com/data.json"  # Replace with real Echo URL if available
    cache_path: "data/echo_data.json"
    
  echo_csv:
    type: "csv"
    path: "data/echo_overrides.csv"
    
  nvd:
    type: "mock"
    mock_file: "ingestion/mock_responses/nvd_responses.json"
    
  osv:
    type: "mock"
    mock_file: "ingestion/mock_responses/osv_responses.json"

rules:
  - id: "R0"
    name: "csv_override"
    priority: 0
    reason_code: "CSV_OVERRIDE"
    
  - id: "R1"
    name: "nvd_rejected"
    priority: 1
    reason_code: "NVD_REJECTED"
    
  - id: "R2"
    name: "upstream_fix"
    priority: 2
    reason_code: "UPSTREAM_FIX"
    
  - id: "R3"
    name: "distro_not_affected"
    priority: 3
    reason_code: "DISTRO_NOT_AFFECTED"
    
  - id: "R4"
    name: "distro_wont_fix"
    priority: 4
    reason_code: "DISTRO_WONT_FIX"
    
  - id: "R5"
    name: "under_investigation"
    priority: 5
    reason_code: "NEW_CVE"
    
  - id: "R6"
    name: "pending_upstream"
    priority: 6
    reason_code: "AWAITING_FIX"

states:
  final:
    - "fixed"
    - "not_applicable"
    - "wont_fix"
  non_final:
    - "pending_upstream"
    - "under_investigation"
    - "unknown"

staleness:
  warning_threshold_days: 60
  critical_threshold_days: 90

explanation_templates:
  CSV_OVERRIDE: "Marked as not applicable by Echo security team. Reason: {csv_reason}. Updated: {csv_updated_at}."
  NVD_REJECTED: "This CVE has been rejected by the National Vulnerability Database. Rejection reason: {nvd_rejection_reason}."
  UPSTREAM_FIX: "Fixed in version {fixed_version}. Source: {fix_source}. Reference: {fix_url}."
  DISTRO_NOT_AFFECTED: "Not affected in {distro}. Reason: {distro_notes}."
  DISTRO_WONT_FIX: "{distro} has marked this as will not fix. Reason: {distro_notes}."
  NEW_CVE: "Recently published CVE under analysis. First observed: {first_seen}. Awaiting upstream signals."
  AWAITING_FIX: "No fix currently available upstream. Last checked: {last_checked}. Sources consulted: {sources_list}."
```

---

## Phase 2: Ingestion Layer

### Step 2.1: base_adapter.py

```python
"""
Abstract base class for all source adapters.
Defines the interface that all adapters must implement.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Any, Optional

@dataclass
class SourceObservation:
    """Normalized observation from any source."""
    observation_id: str           # Unique ID for this observation
    source_id: str                # nvd | osv | echo_csv | echo_data
    cve_id: Optional[str]         # CVE-YYYY-NNNNN or None
    package_name: Optional[str]   # Package name in source's namespace
    observed_at: datetime         # When we fetched this
    source_updated_at: Optional[datetime]  # When source says it was updated
    raw_payload: Dict[str, Any]   # Original source response
    
    # Normalized signals
    fix_available: Optional[bool] = None
    fixed_version: Optional[str] = None
    affected_versions: Optional[str] = None  # Version range expression
    status: Optional[str] = None  # affected | not_affected | under_investigation
    rejection_status: Optional[str] = None  # none | rejected | disputed
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    exploit_available: Optional[bool] = None
    references: Optional[List[str]] = None
    notes: Optional[str] = None

@dataclass 
class SourceHealth:
    """Health status of a source adapter."""
    source_id: str
    is_healthy: bool
    last_fetch: Optional[datetime]
    records_fetched: int
    error_message: Optional[str] = None

class BaseAdapter(ABC):
    """Abstract base class for source adapters."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.source_id: str = ""
        self._last_fetch: Optional[datetime] = None
        self._last_error: Optional[str] = None
    
    @abstractmethod
    def fetch(self) -> List[SourceObservation]:
        """Fetch all records from source. Returns normalized observations."""
        pass
    
    @abstractmethod
    def normalize(self, raw_record: Dict[str, Any]) -> SourceObservation:
        """Transform a raw source record to normalized observation."""
        pass
    
    def get_health(self) -> SourceHealth:
        """Return health status of this adapter."""
        return SourceHealth(
            source_id=self.source_id,
            is_healthy=self._last_error is None,
            last_fetch=self._last_fetch,
            records_fetched=0,
            error_message=self._last_error
        )
```

### Step 2.2: echo_data_adapter.py

```python
"""
Adapter for Echo's data.json - the base advisory corpus.
This represents Echo's published advisories before enrichment.
"""
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
import requests

from .base_adapter import BaseAdapter, SourceObservation

class EchoDataAdapter(BaseAdapter):
    """
    Loads Echo's data.json advisory corpus.
    
    Expected data.json structure (inferred):
    {
        "packages": {
            "package_name": {
                "advisories": [
                    {
                        "cve": "CVE-2024-1234",
                        "severity": "high",
                        "status": "open",
                        ...
                    }
                ]
            }
        }
    }
    
    Adjust parsing based on actual structure.
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.source_id = "echo_data"
        self.url = config.get("url")
        self.cache_path = Path(config.get("cache_path", "data/echo_data.json"))
        
    def fetch(self) -> List[SourceObservation]:
        """Load data.json from cache or URL."""
        self._last_fetch = datetime.utcnow()
        
        try:
            data = self._load_data()
            observations = []
            
            for package_name, package_data in data.get("packages", {}).items():
                advisories = package_data.get("advisories", [])
                for adv in advisories:
                    obs = self.normalize(adv, package_name)
                    if obs:
                        observations.append(obs)
            
            self._last_error = None
            return observations
            
        except Exception as e:
            self._last_error = str(e)
            return []
    
    def _load_data(self) -> Dict[str, Any]:
        """Load from cache, falling back to URL if needed."""
        if self.cache_path.exists():
            with open(self.cache_path, 'r') as f:
                return json.load(f)
        
        # Try URL if no cache
        if self.url:
            response = requests.get(self.url, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            # Cache for future use
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_path, 'w') as f:
                json.dump(data, f)
            
            return data
        
        raise FileNotFoundError(f"No cache at {self.cache_path} and no URL configured")
    
    def normalize(self, raw_record: Dict[str, Any], package_name: str) -> SourceObservation:
        """Transform Echo advisory to normalized observation."""
        cve_id = raw_record.get("cve") or raw_record.get("cve_id")
        
        # Generate stable observation ID
        obs_id = hashlib.md5(
            f"{self.source_id}:{package_name}:{cve_id}".encode()
        ).hexdigest()[:16]
        
        return SourceObservation(
            observation_id=obs_id,
            source_id=self.source_id,
            cve_id=cve_id,
            package_name=package_name,
            observed_at=datetime.utcnow(),
            source_updated_at=None,  # data.json doesn't have per-record timestamps
            raw_payload=raw_record,
            status=raw_record.get("status"),
            cvss_score=raw_record.get("cvss_score"),
            notes=raw_record.get("description")
        )
```

### Step 2.3: echo_csv_adapter.py

```python
"""
Adapter for Echo's internal CSV overrides.
These represent analyst decisions that override upstream sources.
"""
import csv
import hashlib
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from .base_adapter import BaseAdapter, SourceObservation

class EchoCsvAdapter(BaseAdapter):
    """
    Loads Echo's internal CSV with analyst overrides.
    
    Expected CSV columns:
    - package_name: Package identifier
    - cve_id: CVE identifier
    - status: not_applicable | wont_fix | fixed
    - reason: Human-readable reason for override
    - analyst: Who made the decision
    - updated_at: When decision was made
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.source_id = "echo_csv"
        self.path = Path(config.get("path", "data/echo_overrides.csv"))
        self._previous_hash: Optional[str] = None
        
    def fetch(self) -> List[SourceObservation]:
        """Load CSV and return observations."""
        self._last_fetch = datetime.utcnow()
        
        try:
            if not self.path.exists():
                # Return empty if no CSV exists yet
                return []
            
            observations = []
            with open(self.path, 'r', newline='') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    obs = self.normalize(row)
                    if obs:
                        observations.append(obs)
            
            self._last_error = None
            return observations
            
        except Exception as e:
            self._last_error = str(e)
            return []
    
    def normalize(self, raw_record: Dict[str, Any]) -> SourceObservation:
        """Transform CSV row to normalized observation."""
        cve_id = raw_record.get("cve_id", "").strip()
        package_name = raw_record.get("package_name", "").strip()
        
        if not cve_id or not package_name:
            return None
        
        # Generate stable observation ID
        obs_id = hashlib.md5(
            f"{self.source_id}:{package_name}:{cve_id}".encode()
        ).hexdigest()[:16]
        
        # Parse updated_at if present
        updated_at = None
        if raw_record.get("updated_at"):
            try:
                updated_at = datetime.fromisoformat(raw_record["updated_at"])
            except ValueError:
                pass
        
        return SourceObservation(
            observation_id=obs_id,
            source_id=self.source_id,
            cve_id=cve_id,
            package_name=package_name,
            observed_at=datetime.utcnow(),
            source_updated_at=updated_at,
            raw_payload=raw_record,
            status=raw_record.get("status"),
            notes=raw_record.get("reason")
        )
    
    def get_content_hash(self) -> Optional[str]:
        """Get hash of CSV contents for change detection."""
        if not self.path.exists():
            return None
        
        with open(self.path, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    
    def has_changed(self) -> bool:
        """Check if CSV has changed since last fetch."""
        current_hash = self.get_content_hash()
        changed = current_hash != self._previous_hash
        self._previous_hash = current_hash
        return changed
```

### Step 2.4: nvd_adapter.py

```python
"""
Mock NVD adapter with realistic response structure.
In production, this would call the NVD API.
"""
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from .base_adapter import BaseAdapter, SourceObservation

class NvdAdapter(BaseAdapter):
    """
    Mock NVD API adapter.
    
    Real NVD API returns:
    {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "vulnStatus": "Analyzed",  # or "Rejected"
                    "descriptions": [...],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 7.5,
                                "vectorString": "..."
                            }
                        }]
                    },
                    "configurations": [...],
                    "references": [...]
                }
            }
        ]
    }
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.source_id = "nvd"
        self.mock_file = Path(config.get("mock_file", "ingestion/mock_responses/nvd_responses.json"))
        
    def fetch(self) -> List[SourceObservation]:
        """Load mock NVD responses."""
        self._last_fetch = datetime.utcnow()
        
        try:
            if not self.mock_file.exists():
                return []
            
            with open(self.mock_file, 'r') as f:
                data = json.load(f)
            
            observations = []
            for vuln in data.get("vulnerabilities", []):
                obs = self.normalize(vuln)
                if obs:
                    observations.append(obs)
            
            self._last_error = None
            return observations
            
        except Exception as e:
            self._last_error = str(e)
            return []
    
    def normalize(self, raw_record: Dict[str, Any]) -> SourceObservation:
        """Transform NVD vulnerability to normalized observation."""
        cve_data = raw_record.get("cve", {})
        cve_id = cve_data.get("id")
        
        if not cve_id:
            return None
        
        # Generate observation ID
        obs_id = hashlib.md5(
            f"{self.source_id}:{cve_id}".encode()
        ).hexdigest()[:16]
        
        # Extract CVSS score
        cvss_score = None
        cvss_vector = None
        metrics = cve_data.get("metrics", {})
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
        
        # Check rejection status
        vuln_status = cve_data.get("vulnStatus", "")
        rejection_status = "rejected" if vuln_status == "Rejected" else "none"
        
        # Extract references
        refs = cve_data.get("references", [])
        reference_urls = [r.get("url") for r in refs if r.get("url")]
        
        return SourceObservation(
            observation_id=obs_id,
            source_id=self.source_id,
            cve_id=cve_id,
            package_name=None,  # NVD doesn't have package-level granularity
            observed_at=datetime.utcnow(),
            source_updated_at=None,
            raw_payload=raw_record,
            rejection_status=rejection_status,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            references=reference_urls,
            notes=cve_data.get("descriptions", [{}])[0].get("value") if cve_data.get("descriptions") else None
        )
```

### Step 2.5: osv_adapter.py

```python
"""
Mock OSV adapter with realistic response structure.
In production, this would call the OSV API.
"""
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from .base_adapter import BaseAdapter, SourceObservation

class OsvAdapter(BaseAdapter):
    """
    Mock OSV API adapter.
    
    Real OSV API returns:
    {
        "vulns": [
            {
                "id": "GHSA-xxxx-xxxx-xxxx",
                "aliases": ["CVE-2024-1234"],
                "summary": "...",
                "affected": [{
                    "package": {
                        "name": "package-name",
                        "ecosystem": "PyPI"
                    },
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "1.2.3"}
                        ]
                    }]
                }],
                "references": [...]
            }
        ]
    }
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.source_id = "osv"
        self.mock_file = Path(config.get("mock_file", "ingestion/mock_responses/osv_responses.json"))
        
    def fetch(self) -> List[SourceObservation]:
        """Load mock OSV responses."""
        self._last_fetch = datetime.utcnow()
        
        try:
            if not self.mock_file.exists():
                return []
            
            with open(self.mock_file, 'r') as f:
                data = json.load(f)
            
            observations = []
            for vuln in data.get("vulns", []):
                # OSV can have multiple affected packages per vuln
                for affected in vuln.get("affected", []):
                    obs = self.normalize(vuln, affected)
                    if obs:
                        observations.append(obs)
            
            self._last_error = None
            return observations
            
        except Exception as e:
            self._last_error = str(e)
            return []
    
    def normalize(self, vuln: Dict[str, Any], affected: Dict[str, Any]) -> SourceObservation:
        """Transform OSV vulnerability + affected package to normalized observation."""
        # Get CVE ID from aliases
        osv_id = vuln.get("id", "")
        aliases = vuln.get("aliases", [])
        cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
        
        # Get package info
        package_info = affected.get("package", {})
        package_name = package_info.get("name")
        ecosystem = package_info.get("ecosystem")
        
        if not package_name:
            return None
        
        # Generate observation ID (unique per vuln + package)
        obs_id = hashlib.md5(
            f"{self.source_id}:{osv_id}:{package_name}".encode()
        ).hexdigest()[:16]
        
        # Extract fixed version from ranges
        fixed_version = None
        fix_available = False
        ranges = affected.get("ranges", [])
        for r in ranges:
            events = r.get("events", [])
            for event in events:
                if "fixed" in event:
                    fixed_version = event["fixed"]
                    fix_available = True
                    break
        
        # Extract references
        refs = vuln.get("references", [])
        reference_urls = [r.get("url") for r in refs if r.get("url")]
        
        # Look for fix commit URL
        fix_url = None
        for ref in refs:
            if ref.get("type") == "FIX" or "commit" in ref.get("url", "").lower():
                fix_url = ref.get("url")
                break
        
        return SourceObservation(
            observation_id=obs_id,
            source_id=self.source_id,
            cve_id=cve_id,
            package_name=package_name,
            observed_at=datetime.utcnow(),
            source_updated_at=None,
            raw_payload={"vuln": vuln, "affected": affected},
            fix_available=fix_available,
            fixed_version=fixed_version,
            status="affected" if not fix_available else None,
            references=reference_urls,
            notes=vuln.get("summary")
        )
```

### Step 2.6: Create Mock Response Files

Create `ingestion/mock_responses/nvd_responses.json`:

```json
{
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2024-0001",
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "Buffer overflow in example package"}],
        "metrics": {
          "cvssMetricV31": [{
            "cvssData": {"baseScore": 7.5, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}
          }]
        },
        "references": [{"url": "https://example.com/advisory/1"}]
      }
    },
    {
      "cve": {
        "id": "CVE-2024-0002",
        "vulnStatus": "Rejected",
        "descriptions": [{"lang": "en", "value": "Duplicate of CVE-2023-9999"}],
        "metrics": {},
        "references": []
      }
    },
    {
      "cve": {
        "id": "CVE-2024-0003",
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "SQL injection vulnerability"}],
        "metrics": {
          "cvssMetricV31": [{
            "cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
          }]
        },
        "references": [{"url": "https://example.com/advisory/3"}]
      }
    }
  ]
}
```

Create `ingestion/mock_responses/osv_responses.json`:

```json
{
  "vulns": [
    {
      "id": "GHSA-0001-0001-0001",
      "aliases": ["CVE-2024-0001"],
      "summary": "Buffer overflow in example package allows remote code execution",
      "affected": [{
        "package": {"name": "example-package", "ecosystem": "PyPI"},
        "ranges": [{
          "type": "ECOSYSTEM",
          "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]
        }]
      }],
      "references": [
        {"type": "FIX", "url": "https://github.com/example/package/commit/abc123"},
        {"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-0001-0001-0001"}
      ]
    },
    {
      "id": "GHSA-0002-0002-0002",
      "aliases": ["CVE-2024-0003"],
      "summary": "SQL injection vulnerability in database handler",
      "affected": [{
        "package": {"name": "db-handler", "ecosystem": "npm"},
        "ranges": [{
          "type": "ECOSYSTEM",
          "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]
        }]
      }],
      "references": [
        {"type": "FIX", "url": "https://github.com/example/db-handler/commit/def456"}
      ]
    },
    {
      "id": "GHSA-0003-0003-0003",
      "aliases": ["CVE-2024-0004"],
      "summary": "Denial of service via crafted input",
      "affected": [{
        "package": {"name": "parser-lib", "ecosystem": "PyPI"},
        "ranges": [{
          "type": "ECOSYSTEM",
          "events": [{"introduced": "0"}]
        }]
      }],
      "references": []
    }
  ]
}
```

---

## Phase 3: Storage Layer

### Step 3.1: database.py

```python
"""
Database setup and connection management using DuckDB.
DuckDB is used for better dbt compatibility vs SQLite.
"""
import duckdb
from pathlib import Path
from typing import Optional
from datetime import datetime

class Database:
    """
    Manages DuckDB connection and schema setup.
    """
    
    def __init__(self, db_path: str = "advisory_pipeline.duckdb"):
        self.db_path = db_path
        self.conn: Optional[duckdb.DuckDBPyConnection] = None
        
    def connect(self) -> duckdb.DuckDBPyConnection:
        """Get or create database connection."""
        if self.conn is None:
            self.conn = duckdb.connect(self.db_path)
        return self.conn
    
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None
    
    def initialize_schema(self):
        """Create raw data tables for source observations."""
        conn = self.connect()
        
        # Raw source observations (landing zone for adapters)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS raw_echo_advisories (
                observation_id VARCHAR PRIMARY KEY,
                cve_id VARCHAR,
                package_name VARCHAR,
                observed_at TIMESTAMP,
                raw_payload JSON,
                status VARCHAR,
                cvss_score DOUBLE,
                notes VARCHAR,
                run_id VARCHAR
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS raw_echo_csv (
                observation_id VARCHAR PRIMARY KEY,
                cve_id VARCHAR,
                package_name VARCHAR,
                observed_at TIMESTAMP,
                source_updated_at TIMESTAMP,
                raw_payload JSON,
                status VARCHAR,
                reason VARCHAR,
                run_id VARCHAR
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS raw_nvd_observations (
                observation_id VARCHAR PRIMARY KEY,
                cve_id VARCHAR,
                observed_at TIMESTAMP,
                raw_payload JSON,
                rejection_status VARCHAR,
                cvss_score DOUBLE,
                cvss_vector VARCHAR,
                references JSON,
                notes VARCHAR,
                run_id VARCHAR
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS raw_osv_observations (
                observation_id VARCHAR PRIMARY KEY,
                cve_id VARCHAR,
                package_name VARCHAR,
                observed_at TIMESTAMP,
                raw_payload JSON,
                fix_available BOOLEAN,
                fixed_version VARCHAR,
                references JSON,
                notes VARCHAR,
                run_id VARCHAR
            )
        """)
        
        # Pipeline run metadata
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pipeline_runs (
                run_id VARCHAR PRIMARY KEY,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                status VARCHAR,
                advisories_processed INTEGER,
                state_changes INTEGER,
                errors INTEGER,
                metadata JSON
            )
        """)
        
        # Advisory state history (SCD2) - this is the mart, but we create it here
        # for the SCD2 manager. dbt will read/write to this.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS advisory_state_history (
                history_id VARCHAR PRIMARY KEY,
                advisory_id VARCHAR,
                cve_id VARCHAR,
                package_name VARCHAR,
                state VARCHAR,
                state_type VARCHAR,
                fixed_version VARCHAR,
                confidence VARCHAR,
                explanation VARCHAR,
                reason_code VARCHAR,
                evidence JSON,
                decision_rule VARCHAR,
                contributing_sources JSON,
                dissenting_sources JSON,
                effective_from TIMESTAMP,
                effective_to TIMESTAMP,
                is_current BOOLEAN,
                run_id VARCHAR,
                staleness_score DOUBLE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create indexes
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ash_advisory ON advisory_state_history(advisory_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ash_current ON advisory_state_history(is_current)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ash_cve ON advisory_state_history(cve_id)")
        
    def get_current_run_id(self) -> str:
        """Generate a new run ID."""
        return f"run_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
```

### Step 3.2: loader.py

```python
"""
Loads source observations into raw tables.
"""
import json
from datetime import datetime
from typing import List

from ingestion.base_adapter import SourceObservation
from .database import Database

class SourceLoader:
    """Loads observations from adapters into raw tables."""
    
    def __init__(self, database: Database):
        self.db = database
        
    def load_echo_advisories(self, observations: List[SourceObservation], run_id: str):
        """Load Echo advisory observations."""
        conn = self.db.connect()
        
        # Clear previous run's data (incremental load pattern)
        # In production, you'd want more sophisticated handling
        conn.execute("DELETE FROM raw_echo_advisories WHERE run_id = ?", [run_id])
        
        for obs in observations:
            conn.execute("""
                INSERT OR REPLACE INTO raw_echo_advisories 
                (observation_id, cve_id, package_name, observed_at, raw_payload, 
                 status, cvss_score, notes, run_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                obs.observation_id,
                obs.cve_id,
                obs.package_name,
                obs.observed_at,
                json.dumps(obs.raw_payload),
                obs.status,
                obs.cvss_score,
                obs.notes,
                run_id
            ])
    
    def load_echo_csv(self, observations: List[SourceObservation], run_id: str):
        """Load Echo CSV observations."""
        conn = self.db.connect()
        conn.execute("DELETE FROM raw_echo_csv WHERE run_id = ?", [run_id])
        
        for obs in observations:
            conn.execute("""
                INSERT OR REPLACE INTO raw_echo_csv
                (observation_id, cve_id, package_name, observed_at, source_updated_at,
                 raw_payload, status, reason, run_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                obs.observation_id,
                obs.cve_id,
                obs.package_name,
                obs.observed_at,
                obs.source_updated_at,
                json.dumps(obs.raw_payload),
                obs.status,
                obs.notes,  # reason is stored in notes
                run_id
            ])
    
    def load_nvd_observations(self, observations: List[SourceObservation], run_id: str):
        """Load NVD observations."""
        conn = self.db.connect()
        conn.execute("DELETE FROM raw_nvd_observations WHERE run_id = ?", [run_id])
        
        for obs in observations:
            conn.execute("""
                INSERT OR REPLACE INTO raw_nvd_observations
                (observation_id, cve_id, observed_at, raw_payload, rejection_status,
                 cvss_score, cvss_vector, references, notes, run_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                obs.observation_id,
                obs.cve_id,
                obs.observed_at,
                json.dumps(obs.raw_payload),
                obs.rejection_status,
                obs.cvss_score,
                obs.cvss_vector,
                json.dumps(obs.references) if obs.references else None,
                obs.notes,
                run_id
            ])
    
    def load_osv_observations(self, observations: List[SourceObservation], run_id: str):
        """Load OSV observations."""
        conn = self.db.connect()
        conn.execute("DELETE FROM raw_osv_observations WHERE run_id = ?", [run_id])
        
        for obs in observations:
            conn.execute("""
                INSERT OR REPLACE INTO raw_osv_observations
                (observation_id, cve_id, package_name, observed_at, raw_payload,
                 fix_available, fixed_version, references, notes, run_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                obs.observation_id,
                obs.cve_id,
                obs.package_name,
                obs.observed_at,
                json.dumps(obs.raw_payload),
                obs.fix_available,
                obs.fixed_version,
                json.dumps(obs.references) if obs.references else None,
                obs.notes,
                run_id
            ])
```

### Step 3.3: scd2_manager.py

```python
"""
SCD Type 2 state management for advisory history.
Handles detecting changes and writing history records.
"""
import hashlib
import json
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from .database import Database

@dataclass
class AdvisoryState:
    """Current state of an advisory."""
    advisory_id: str
    cve_id: str
    package_name: str
    state: str
    state_type: str  # final | non_final
    fixed_version: Optional[str]
    confidence: str  # high | medium | low
    explanation: str
    reason_code: str
    evidence: Dict[str, Any]
    decision_rule: str
    contributing_sources: List[str]
    dissenting_sources: List[str]
    staleness_score: float

class SCD2Manager:
    """
    Manages SCD Type 2 operations for advisory state history.
    
    Key operations:
    1. Compare new state with current state
    2. If changed: close current record, insert new record
    3. If unchanged: no action (skip)
    """
    
    def __init__(self, database: Database):
        self.db = database
    
    def get_current_state(self, advisory_id: str) -> Optional[Dict[str, Any]]:
        """Get current state for an advisory."""
        conn = self.db.connect()
        result = conn.execute("""
            SELECT * FROM advisory_state_history
            WHERE advisory_id = ? AND is_current = TRUE
        """, [advisory_id]).fetchone()
        
        if result:
            columns = [desc[0] for desc in conn.description]
            return dict(zip(columns, result))
        return None
    
    def has_state_changed(self, current: Optional[Dict], new_state: AdvisoryState) -> bool:
        """
        Determine if state has changed enough to warrant new history record.
        
        Changes that trigger new record:
        - state changed
        - fixed_version changed (for fixed state)
        - explanation changed significantly
        - confidence changed
        """
        if current is None:
            return True
        
        if current["state"] != new_state.state:
            return True
        
        if current["fixed_version"] != new_state.fixed_version:
            return True
        
        if current["confidence"] != new_state.confidence:
            return True
        
        if current["reason_code"] != new_state.reason_code:
            return True
        
        return False
    
    def apply_state(self, new_state: AdvisoryState, run_id: str) -> bool:
        """
        Apply new state, managing SCD2 history.
        
        Returns True if a new history record was created.
        """
        conn = self.db.connect()
        current = self.get_current_state(new_state.advisory_id)
        
        if not self.has_state_changed(current, new_state):
            return False
        
        now = datetime.utcnow()
        
        # Close current record if exists
        if current:
            conn.execute("""
                UPDATE advisory_state_history
                SET is_current = FALSE, effective_to = ?
                WHERE advisory_id = ? AND is_current = TRUE
            """, [now, new_state.advisory_id])
        
        # Generate new history ID
        history_id = hashlib.md5(
            f"{new_state.advisory_id}:{now.isoformat()}".encode()
        ).hexdigest()[:16]
        
        # Insert new current record
        conn.execute("""
            INSERT INTO advisory_state_history
            (history_id, advisory_id, cve_id, package_name, state, state_type,
             fixed_version, confidence, explanation, reason_code, evidence,
             decision_rule, contributing_sources, dissenting_sources,
             effective_from, effective_to, is_current, run_id, staleness_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, TRUE, ?, ?)
        """, [
            history_id,
            new_state.advisory_id,
            new_state.cve_id,
            new_state.package_name,
            new_state.state,
            new_state.state_type,
            new_state.fixed_version,
            new_state.confidence,
            new_state.explanation,
            new_state.reason_code,
            json.dumps(new_state.evidence),
            new_state.decision_rule,
            json.dumps(new_state.contributing_sources),
            json.dumps(new_state.dissenting_sources),
            now,
            run_id,
            new_state.staleness_score
        ])
        
        return True
    
    def get_state_at_time(self, advisory_id: str, point_in_time: datetime) -> Optional[Dict]:
        """Point-in-time query for advisory state."""
        conn = self.db.connect()
        result = conn.execute("""
            SELECT * FROM advisory_state_history
            WHERE advisory_id = ?
              AND effective_from <= ?
              AND (effective_to IS NULL OR effective_to > ?)
        """, [advisory_id, point_in_time, point_in_time]).fetchone()
        
        if result:
            columns = [desc[0] for desc in conn.description]
            return dict(zip(columns, result))
        return None
    
    def get_history(self, advisory_id: str) -> List[Dict]:
        """Get full history for an advisory."""
        conn = self.db.connect()
        results = conn.execute("""
            SELECT * FROM advisory_state_history
            WHERE advisory_id = ?
            ORDER BY effective_from ASC
        """, [advisory_id]).fetchall()
        
        columns = [desc[0] for desc in conn.description]
        return [dict(zip(columns, row)) for row in results]
```

---

## Phase 4: dbt Project

### Step 4.1: dbt_project/dbt_project.yml

```yaml
name: 'advisory_pipeline'
version: '1.0.0'
config-version: 2

profile: 'advisory_pipeline'

model-paths: ["models"]
analysis-paths: ["analyses"]
test-paths: ["tests"]
seed-paths: ["seeds"]
macro-paths: ["macros"]

target-path: "target"
clean-targets:
  - "target"
  - "dbt_packages"

vars:
  current_run_id: "{{ env_var('PIPELINE_RUN_ID', 'manual_run') }}"

models:
  advisory_pipeline:
    staging:
      +materialized: view
    intermediate:
      +materialized: table
    marts:
      +materialized: table
```

### Step 4.2: dbt_project/profiles.yml

```yaml
advisory_pipeline:
  target: dev
  outputs:
    dev:
      type: duckdb
      path: '../advisory_pipeline.duckdb'
      threads: 4
```

### Step 4.3: dbt_project/models/sources.yml

```yaml
version: 2

sources:
  - name: raw
    description: "Raw source observations loaded by Python adapters"
    tables:
      - name: raw_echo_advisories
        description: "Echo's base advisory corpus from data.json"
        columns:
          - name: observation_id
            tests: [unique, not_null]
          - name: cve_id
          - name: package_name
            
      - name: raw_echo_csv
        description: "Internal analyst overrides from CSV"
        columns:
          - name: observation_id
            tests: [unique, not_null]
            
      - name: raw_nvd_observations
        description: "NVD CVE data"
        columns:
          - name: observation_id
            tests: [unique, not_null]
            
      - name: raw_osv_observations
        description: "OSV vulnerability data"
        columns:
          - name: observation_id
            tests: [unique, not_null]
            
      - name: advisory_state_history
        description: "SCD2 advisory state history (also managed by Python)"
        
      - name: pipeline_runs
        description: "Pipeline run metadata"
```

### Step 4.4: dbt_project/models/staging/stg_echo_advisories.sql

```sql
-- Staging model for Echo base advisories
-- Validates and cleans raw data

with source as (
    select * from {{ source('raw', 'raw_echo_advisories') }}
),

validated as (
    select
        observation_id,
        -- Validate CVE ID format
        case 
            when cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$' then cve_id
            else null
        end as cve_id,
        nullif(trim(package_name), '') as package_name,
        observed_at,
        raw_payload,
        lower(trim(status)) as status,
        cvss_score,
        notes,
        run_id,
        
        -- Flag invalid records
        case when cve_id !~ '^CVE-[0-9]{4}-[0-9]{4,}$' then true else false end as has_invalid_cve
        
    from source
    where package_name is not null
      and trim(package_name) != ''
)

select * from validated
```

### Step 4.5: dbt_project/models/staging/stg_echo_csv.sql

```sql
-- Staging model for Echo CSV overrides
-- These are internal analyst decisions that override upstream

with source as (
    select * from {{ source('raw', 'raw_echo_csv') }}
),

cleaned as (
    select
        observation_id,
        upper(trim(cve_id)) as cve_id,
        lower(trim(package_name)) as package_name,
        observed_at,
        source_updated_at,
        raw_payload,
        lower(trim(status)) as override_status,
        reason as override_reason,
        run_id
        
    from source
    where cve_id is not null
      and package_name is not null
)

select * from cleaned
```

### Step 4.6: dbt_project/models/staging/stg_nvd_observations.sql

```sql
-- Staging model for NVD observations

with source as (
    select * from {{ source('raw', 'raw_nvd_observations') }}
),

cleaned as (
    select
        observation_id,
        upper(trim(cve_id)) as cve_id,
        observed_at,
        raw_payload,
        lower(trim(rejection_status)) as rejection_status,
        cvss_score,
        cvss_vector,
        references,
        notes,
        run_id,
        
        -- Derive severity from CVSS
        case
            when cvss_score >= 9.0 then 'critical'
            when cvss_score >= 7.0 then 'high'
            when cvss_score >= 4.0 then 'medium'
            when cvss_score >= 0.1 then 'low'
            else 'none'
        end as severity
        
    from source
    where cve_id is not null
)

select * from cleaned
```

### Step 4.7: dbt_project/models/staging/stg_osv_observations.sql

```sql
-- Staging model for OSV observations

with source as (
    select * from {{ source('raw', 'raw_osv_observations') }}
),

cleaned as (
    select
        observation_id,
        upper(trim(cve_id)) as cve_id,
        lower(trim(package_name)) as package_name,
        observed_at,
        raw_payload,
        coalesce(fix_available, false) as fix_available,
        nullif(trim(fixed_version), '') as fixed_version,
        references,
        notes,
        run_id,
        
        -- Extract fix URL if present in references
        case 
            when references is not null then 
                json_extract_string(references, '$[0]')
            else null
        end as primary_reference
        
    from source
    where cve_id is not null or package_name is not null
)

select * from cleaned
```

### Step 4.8: dbt_project/models/intermediate/int_source_observations.sql

```sql
-- Unified source observations across all sources
-- This is the canonical view of all signals

with echo_advisories as (
    select
        observation_id,
        'echo_data' as source_id,
        cve_id,
        package_name,
        observed_at,
        null::timestamp as source_updated_at,
        status,
        null::varchar as override_status,
        null::varchar as override_reason,
        null::varchar as rejection_status,
        cvss_score,
        null::varchar as cvss_vector,
        null::boolean as fix_available,
        null::varchar as fixed_version,
        notes,
        run_id
    from {{ ref('stg_echo_advisories') }}
    where not has_invalid_cve
),

echo_csv as (
    select
        observation_id,
        'echo_csv' as source_id,
        cve_id,
        package_name,
        observed_at,
        source_updated_at,
        null::varchar as status,
        override_status,
        override_reason,
        null::varchar as rejection_status,
        null::double as cvss_score,
        null::varchar as cvss_vector,
        null::boolean as fix_available,
        null::varchar as fixed_version,
        null::varchar as notes,
        run_id
    from {{ ref('stg_echo_csv') }}
),

nvd as (
    select
        observation_id,
        'nvd' as source_id,
        cve_id,
        null::varchar as package_name,
        observed_at,
        null::timestamp as source_updated_at,
        null::varchar as status,
        null::varchar as override_status,
        null::varchar as override_reason,
        rejection_status,
        cvss_score,
        cvss_vector,
        null::boolean as fix_available,
        null::varchar as fixed_version,
        notes,
        run_id
    from {{ ref('stg_nvd_observations') }}
),

osv as (
    select
        observation_id,
        'osv' as source_id,
        cve_id,
        package_name,
        observed_at,
        null::timestamp as source_updated_at,
        null::varchar as status,
        null::varchar as override_status,
        null::varchar as override_reason,
        null::varchar as rejection_status,
        null::double as cvss_score,
        null::varchar as cvss_vector,
        fix_available,
        fixed_version,
        notes,
        run_id
    from {{ ref('stg_osv_observations') }}
),

unioned as (
    select * from echo_advisories
    union all
    select * from echo_csv
    union all
    select * from nvd
    union all
    select * from osv
)

select 
    *,
    -- Source priority for conflict resolution
    case source_id
        when 'echo_csv' then 0
        when 'nvd' then 1
        when 'osv' then 2
        when 'echo_data' then 3
        else 99
    end as source_priority
from unioned
```

### Step 4.9: dbt_project/models/intermediate/int_enriched_advisories.sql

```sql
-- Enriched advisories with aggregated signals from all sources
-- Implements conflict resolution logic

with observations as (
    select * from {{ ref('int_source_observations') }}
),

-- Get unique advisory identifiers (package + CVE combinations)
advisory_keys as (
    select distinct
        coalesce(package_name, 'UNKNOWN') || ':' || cve_id as advisory_id,
        cve_id,
        package_name
    from observations
    where cve_id is not null
),

-- Aggregate CSV overrides (highest priority)
csv_overrides as (
    select
        coalesce(package_name, 'UNKNOWN') || ':' || cve_id as advisory_id,
        override_status,
        override_reason,
        source_updated_at as csv_updated_at
    from observations
    where source_id = 'echo_csv'
      and override_status is not null
),

-- Aggregate NVD signals
nvd_signals as (
    select
        cve_id,
        max(rejection_status) as nvd_rejection_status,
        max(cvss_score) as nvd_cvss_score,
        max(cvss_vector) as nvd_cvss_vector,
        max(notes) as nvd_description
    from observations
    where source_id = 'nvd'
    group by cve_id
),

-- Aggregate OSV signals (package-level)
osv_signals as (
    select
        coalesce(package_name, 'UNKNOWN') || ':' || cve_id as advisory_id,
        bool_or(fix_available) as osv_fix_available,
        max(fixed_version) as osv_fixed_version,
        max(notes) as osv_summary
    from observations
    where source_id = 'osv'
    group by coalesce(package_name, 'UNKNOWN') || ':' || cve_id
),

-- List contributing sources per advisory
source_contributions as (
    select
        coalesce(package_name, 'UNKNOWN') || ':' || cve_id as advisory_id,
        list(distinct source_id order by source_priority) as contributing_sources
    from observations
    where cve_id is not null
    group by coalesce(package_name, 'UNKNOWN') || ':' || cve_id
),

-- Combine all signals
enriched as (
    select
        ak.advisory_id,
        ak.cve_id,
        ak.package_name,
        
        -- CSV override signals
        csv.override_status,
        csv.override_reason,
        csv.csv_updated_at,
        
        -- NVD signals
        nvd.nvd_rejection_status,
        nvd.nvd_cvss_score,
        nvd.nvd_cvss_vector,
        nvd.nvd_description,
        
        -- OSV signals
        osv.osv_fix_available,
        osv.osv_fixed_version,
        osv.osv_summary,
        
        -- Resolved signals (conflict resolution)
        -- Fix available: TRUE if any source says true
        coalesce(osv.osv_fix_available, false) as fix_available,
        
        -- Fixed version: prefer OSV (has package context)
        osv.osv_fixed_version as fixed_version,
        
        -- CVSS: prefer NVD (authoritative)
        nvd.nvd_cvss_score as cvss_score,
        
        -- Is rejected: only from NVD
        nvd.nvd_rejection_status = 'rejected' as is_rejected,
        
        -- Contributing sources
        sc.contributing_sources,
        
        -- Calculate staleness (simplified)
        0.0 as staleness_score
        
    from advisory_keys ak
    left join csv_overrides csv on ak.advisory_id = csv.advisory_id
    left join nvd_signals nvd on ak.cve_id = nvd.cve_id
    left join osv_signals osv on ak.advisory_id = osv.advisory_id
    left join source_contributions sc on ak.advisory_id = sc.advisory_id
)

select * from enriched
```

### Step 4.10: dbt_project/models/intermediate/int_decision_inputs.sql

```sql
-- Prepare inputs for decision engine
-- Adds derived fields needed by rules

with enriched as (
    select * from {{ ref('int_enriched_advisories') }}
),

with_derived as (
    select
        *,
        
        -- Confidence scoring
        case
            when override_status is not null then 'high'  -- Internal override = high confidence
            when fix_available and fixed_version is not null then 'high'
            when is_rejected then 'high'
            when cvss_score is not null then 'medium'
            else 'low'
        end as confidence,
        
        -- Count of sources with signals
        list_count(contributing_sources) as source_count,
        
        -- Has any substantive signal
        case
            when override_status is not null then true
            when is_rejected then true
            when fix_available then true
            when cvss_score is not null then true
            else false
        end as has_signal
        
    from enriched
)

select * from with_derived
```

### Step 4.11: dbt_project/models/marts/mart_advisory_decisions.sql

```sql
-- Decision engine: Apply rule chain to determine state
-- Each advisory gets exactly one state based on first matching rule

with inputs as (
    select * from {{ ref('int_decision_inputs') }}
),

decisions as (
    select
        advisory_id,
        cve_id,
        package_name,
        
        -- Apply rule chain (first match wins)
        case
            -- Rule 0: CSV Override (Priority 0)
            when override_status = 'not_applicable' then 'not_applicable'
            
            -- Rule 1: NVD Rejected (Priority 1)
            when is_rejected then 'not_applicable'
            
            -- Rule 2: Upstream Fix (Priority 2)
            when fix_available and fixed_version is not null then 'fixed'
            
            -- Rule 3: Distro Not Affected - would need distro data
            -- Skipped in prototype
            
            -- Rule 4: Distro Won't Fix - would need distro data
            -- Skipped in prototype
            
            -- Rule 5: Under Investigation (new CVE, no signals)
            when not has_signal then 'under_investigation'
            
            -- Rule 6: Default - Pending Upstream
            else 'pending_upstream'
        end as state,
        
        -- Determine which rule fired
        case
            when override_status = 'not_applicable' then 'R0:csv_override'
            when is_rejected then 'R1:nvd_rejected'
            when fix_available and fixed_version is not null then 'R2:upstream_fix'
            when not has_signal then 'R5:under_investigation'
            else 'R6:pending_upstream'
        end as decision_rule,
        
        -- Reason code for explanation
        case
            when override_status = 'not_applicable' then 'CSV_OVERRIDE'
            when is_rejected then 'NVD_REJECTED'
            when fix_available and fixed_version is not null then 'UPSTREAM_FIX'
            when not has_signal then 'NEW_CVE'
            else 'AWAITING_FIX'
        end as reason_code,
        
        -- State type
        case
            when override_status = 'not_applicable' then 'final'
            when is_rejected then 'final'
            when fix_available and fixed_version is not null then 'final'
            else 'non_final'
        end as state_type,
        
        -- Fixed version (only relevant for 'fixed' state)
        case
            when fix_available and fixed_version is not null then fixed_version
            else null
        end as fixed_version,
        
        confidence,
        
        -- Build evidence JSON
        json_object(
            'csv_override', override_status,
            'csv_reason', override_reason,
            'is_rejected', is_rejected,
            'fix_available', fix_available,
            'fixed_version', fixed_version,
            'cvss_score', cvss_score,
            'source_count', source_count
        ) as evidence,
        
        contributing_sources,
        
        -- Dissenting sources (simplified - sources that disagree)
        case
            when override_status = 'not_applicable' and fix_available then 
                '["osv"]'::json
            else 
                '[]'::json
        end as dissenting_sources,
        
        staleness_score,
        
        current_timestamp as decided_at,
        '{{ var("current_run_id") }}' as run_id
        
    from inputs
)

select * from decisions
```

### Step 4.12: dbt_project/models/marts/mart_advisory_current.sql

```sql
-- Current advisory state view
-- This is what gets published as advisory_current.json

with decisions as (
    select * from {{ ref('mart_advisory_decisions') }}
),

with_explanations as (
    select
        d.*,
        
        -- Generate explanation from template
        case d.reason_code
            when 'CSV_OVERRIDE' then 
                'Marked as not applicable by Echo security team. Reason: ' || 
                coalesce(json_extract_string(d.evidence, '$.csv_reason'), 'Internal policy') || '.'
            when 'NVD_REJECTED' then 
                'This CVE has been rejected by the National Vulnerability Database.'
            when 'UPSTREAM_FIX' then 
                'Fixed in version ' || coalesce(d.fixed_version, 'unknown') || 
                '. Fix available from upstream.'
            when 'NEW_CVE' then 
                'Recently published CVE under analysis. Awaiting upstream signals.'
            when 'AWAITING_FIX' then 
                'No fix currently available upstream. Monitoring for updates.'
            else 
                'Status determined by enrichment pipeline.'
        end as explanation
        
    from decisions d
)

select
    advisory_id,
    cve_id,
    package_name,
    state,
    state_type,
    fixed_version,
    confidence,
    explanation,
    reason_code,
    evidence,
    decision_rule,
    contributing_sources,
    dissenting_sources,
    staleness_score,
    decided_at,
    run_id
from with_explanations
```

### Step 4.13: dbt_project/macros/generate_explanation.sql

```sql
-- Macro for generating explanations from templates

{% macro generate_explanation(reason_code, evidence) %}
    case {{ reason_code }}
        when 'CSV_OVERRIDE' then 
            concat('Marked as not applicable by Echo security team. Reason: ',
                   coalesce(json_extract_string({{ evidence }}, '$.csv_reason'), 'Internal policy'),
                   '.')
        when 'NVD_REJECTED' then 
            'This CVE has been rejected by the National Vulnerability Database.'
        when 'UPSTREAM_FIX' then 
            concat('Fixed in version ', 
                   coalesce(json_extract_string({{ evidence }}, '$.fixed_version'), 'unknown'),
                   '. Fix available from upstream.')
        when 'NEW_CVE' then 
            'Recently published CVE under analysis. Awaiting upstream signals.'
        when 'AWAITING_FIX' then 
            'No fix currently available upstream. Monitoring for updates.'
        else 
            'Status determined by enrichment pipeline.'
    end
{% endmacro %}
```

### Step 4.14: dbt_project/tests/assert_valid_transitions.sql

```sql
-- Test: Ensure no invalid state transitions occurred
-- Invalid: fixed -> pending_upstream (regression)

with current_run as (
    select * from {{ ref('mart_advisory_current') }}
),

previous_state as (
    select 
        advisory_id,
        state as previous_state
    from {{ source('raw', 'advisory_state_history') }}
    where is_current = false
      and effective_to = (
          select max(effective_to) 
          from {{ source('raw', 'advisory_state_history') }} h2
          where h2.advisory_id = advisory_state_history.advisory_id
            and h2.is_current = false
      )
),

transitions as (
    select
        c.advisory_id,
        p.previous_state,
        c.state as new_state
    from current_run c
    inner join previous_state p on c.advisory_id = p.advisory_id
    where p.previous_state != c.state
),

invalid_transitions as (
    select *
    from transitions
    where 
        -- Regression: final state moving to non-final without trigger
        (previous_state = 'fixed' and new_state = 'pending_upstream')
        or (previous_state = 'not_applicable' and new_state = 'pending_upstream')
)

select * from invalid_transitions
-- Test passes if no rows returned
```

---

## Phase 5: Decisioning Layer (Python)

### Step 5.1: decisioning/rules.py

```python
"""
Rule definitions for the decision engine.
Each rule has a condition, resulting state, and explanation template.
"""
from dataclasses import dataclass
from typing import Callable, Dict, Any, Optional

@dataclass
class Rule:
    """A decision rule in the rule chain."""
    id: str
    name: str
    priority: int
    condition: Callable[[Dict[str, Any]], bool]
    state: str
    state_type: str  # final | non_final
    reason_code: str
    explanation_template: str

# Rule definitions
RULES = [
    Rule(
        id="R0",
        name="csv_override",
        priority=0,
        condition=lambda e: e.get("override_status") == "not_applicable",
        state="not_applicable",
        state_type="final",
        reason_code="CSV_OVERRIDE",
        explanation_template="Marked as not applicable by Echo security team. Reason: {override_reason}."
    ),
    Rule(
        id="R1",
        name="nvd_rejected",
        priority=1,
        condition=lambda e: e.get("is_rejected") == True,
        state="not_applicable",
        state_type="final",
        reason_code="NVD_REJECTED",
        explanation_template="This CVE has been rejected by the National Vulnerability Database."
    ),
    Rule(
        id="R2",
        name="upstream_fix",
        priority=2,
        condition=lambda e: e.get("fix_available") and e.get("fixed_version"),
        state="fixed",
        state_type="final",
        reason_code="UPSTREAM_FIX",
        explanation_template="Fixed in version {fixed_version}. Fix available from upstream."
    ),
    Rule(
        id="R5",
        name="under_investigation",
        priority=5,
        condition=lambda e: not e.get("has_signal"),
        state="under_investigation",
        state_type="non_final",
        reason_code="NEW_CVE",
        explanation_template="Recently published CVE under analysis. Awaiting upstream signals."
    ),
    Rule(
        id="R6",
        name="pending_upstream",
        priority=6,
        condition=lambda e: True,  # Default catch-all
        state="pending_upstream",
        state_type="non_final",
        reason_code="AWAITING_FIX",
        explanation_template="No fix currently available upstream. Monitoring for updates."
    ),
]

def get_rules_sorted() -> list[Rule]:
    """Get rules sorted by priority (ascending)."""
    return sorted(RULES, key=lambda r: r.priority)
```

### Step 5.2: decisioning/explainer.py

```python
"""
Explanation generator.
Fills templates with evidence values.
"""
import re
from typing import Dict, Any

def generate_explanation(template: str, evidence: Dict[str, Any]) -> str:
    """
    Generate explanation by substituting template variables.
    
    Template variables are {variable_name} patterns.
    Missing values are replaced with 'unknown'.
    """
    def replace_var(match):
        var_name = match.group(1)
        value = evidence.get(var_name)
        if value is None:
            return "unknown"
        return str(value)
    
    pattern = r'\{(\w+)\}'
    return re.sub(pattern, replace_var, template)


def format_sources_list(sources: list) -> str:
    """Format list of sources for explanation."""
    if not sources:
        return "none"
    if len(sources) == 1:
        return sources[0].upper()
    return ", ".join(s.upper() for s in sources[:-1]) + f" and {sources[-1].upper()}"
```

### Step 5.3: decisioning/state_machine.py

```python
"""
State machine definitions and transition validation.
"""
from typing import Set, Tuple

# State definitions
FINAL_STATES: Set[str] = {"fixed", "not_applicable", "wont_fix"}
NON_FINAL_STATES: Set[str] = {"pending_upstream", "under_investigation", "unknown"}
ALL_STATES: Set[str] = FINAL_STATES | NON_FINAL_STATES

# Valid transitions (from_state, to_state)
VALID_TRANSITIONS: Set[Tuple[str, str]] = {
    # From unknown (initial)
    ("unknown", "fixed"),
    ("unknown", "not_applicable"),
    ("unknown", "wont_fix"),
    ("unknown", "pending_upstream"),
    ("unknown", "under_investigation"),
    
    # From under_investigation
    ("under_investigation", "fixed"),
    ("under_investigation", "not_applicable"),
    ("under_investigation", "wont_fix"),
    ("under_investigation", "pending_upstream"),
    
    # From pending_upstream
    ("pending_upstream", "fixed"),
    ("pending_upstream", "not_applicable"),
    ("pending_upstream", "wont_fix"),
    
    # Rare but valid
    ("fixed", "not_applicable"),  # CVE rejected after fix
    ("not_applicable", "fixed"),  # Re-evaluation
    ("wont_fix", "fixed"),        # Upstream changed decision
}

def is_valid_transition(from_state: str, to_state: str) -> bool:
    """Check if a state transition is valid."""
    if from_state == to_state:
        return True  # No change is always valid
    return (from_state, to_state) in VALID_TRANSITIONS

def get_state_type(state: str) -> str:
    """Get whether a state is final or non-final."""
    if state in FINAL_STATES:
        return "final"
    return "non_final"

def should_reprocess(state: str, staleness_score: float = 0.0) -> bool:
    """
    Determine if an advisory should be reprocessed.
    
    Non-final states always reprocess.
    Final states reprocess if stale.
    """
    if state in NON_FINAL_STATES:
        return True
    if staleness_score > 0.7:
        return True
    return False
```

---

## Phase 6: Observability Layer

### Step 6.1: observability/metrics.py

```python
"""
Metrics collection for pipeline runs.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Any
from collections import defaultdict

@dataclass
class RunMetrics:
    """Metrics for a single pipeline run."""
    run_id: str
    started_at: datetime
    completed_at: datetime = None
    
    # Counts
    advisories_total: int = 0
    advisories_processed: int = 0
    state_changes: int = 0
    errors: int = 0
    
    # State distribution
    state_counts: Dict[str, int] = field(default_factory=dict)
    
    # Transitions
    transitions: Dict[tuple, int] = field(default_factory=lambda: defaultdict(int))
    
    # Rules fired
    rules_fired: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    # Source health
    source_health: Dict[str, Dict] = field(default_factory=dict)
    
    # Quality issues
    quality_issues: List[Dict] = field(default_factory=list)
    
    def record_transition(self, from_state: str, to_state: str):
        """Record a state transition."""
        if from_state != to_state:
            self.transitions[(from_state, to_state)] += 1
            self.state_changes += 1
    
    def record_rule_fired(self, rule_id: str):
        """Record that a rule was used."""
        self.rules_fired[rule_id] += 1
    
    def record_error(self, error: str, context: Dict = None):
        """Record an error."""
        self.errors += 1
        self.quality_issues.append({
            "type": "error",
            "message": error,
            "context": context
        })
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "run_id": self.run_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "advisories_total": self.advisories_total,
            "advisories_processed": self.advisories_processed,
            "state_changes": self.state_changes,
            "errors": self.errors,
            "state_counts": self.state_counts,
            "transitions": {f"{k[0]}->{k[1]}": v for k, v in self.transitions.items()},
            "rules_fired": dict(self.rules_fired),
            "source_health": self.source_health,
            "quality_issues": self.quality_issues
        }
```

### Step 6.2: observability/quality_checks.py

```python
"""
Data quality checks run after each pipeline execution.
"""
from typing import List, Dict, Any
from dataclasses import dataclass

@dataclass
class QualityCheckResult:
    """Result of a quality check."""
    check_name: str
    passed: bool
    message: str
    details: Dict[str, Any] = None

class QualityChecker:
    """Runs data quality checks against pipeline output."""
    
    def __init__(self, database):
        self.db = database
    
    def run_all_checks(self) -> List[QualityCheckResult]:
        """Run all quality checks."""
        results = []
        results.append(self.check_no_null_states())
        results.append(self.check_no_orphan_packages())
        results.append(self.check_explanation_completeness())
        results.append(self.check_fixed_has_version())
        results.append(self.check_cve_format())
        results.append(self.check_stalled_cves())
        return results
    
    def check_no_null_states(self) -> QualityCheckResult:
        """Ensure no advisory has null state."""
        conn = self.db.connect()
        result = conn.execute("""
            SELECT count(*) FROM advisory_state_history
            WHERE is_current = true AND state IS NULL
        """).fetchone()[0]
        
        return QualityCheckResult(
            check_name="no_null_states",
            passed=result == 0,
            message=f"{result} advisories with null state" if result > 0 else "All advisories have state",
            details={"null_count": result}
        )
    
    def check_explanation_completeness(self) -> QualityCheckResult:
        """Ensure all advisories have explanations."""
        conn = self.db.connect()
        result = conn.execute("""
            SELECT count(*) FROM advisory_state_history
            WHERE is_current = true 
              AND (explanation IS NULL OR trim(explanation) = '')
        """).fetchone()[0]
        
        return QualityCheckResult(
            check_name="explanation_completeness",
            passed=result == 0,
            message=f"{result} advisories missing explanation" if result > 0 else "All advisories have explanations",
            details={"missing_count": result}
        )
    
    def check_fixed_has_version(self) -> QualityCheckResult:
        """Ensure 'fixed' state has fixed_version."""
        conn = self.db.connect()
        result = conn.execute("""
            SELECT count(*) FROM advisory_state_history
            WHERE is_current = true 
              AND state = 'fixed'
              AND (fixed_version IS NULL OR trim(fixed_version) = '')
        """).fetchone()[0]
        
        return QualityCheckResult(
            check_name="fixed_has_version",
            passed=result == 0,
            message=f"{result} fixed advisories without version" if result > 0 else "All fixed advisories have version",
            details={"missing_count": result}
        )
    
    def check_cve_format(self) -> QualityCheckResult:
        """Check CVE ID format validity."""
        conn = self.db.connect()
        result = conn.execute("""
            SELECT count(*) FROM advisory_state_history
            WHERE is_current = true 
              AND cve_id IS NOT NULL
              AND cve_id NOT SIMILAR TO 'CVE-[0-9]{4}-[0-9]{4,}'
        """).fetchone()[0]
        
        return QualityCheckResult(
            check_name="cve_format",
            passed=result == 0,
            message=f"{result} invalid CVE formats" if result > 0 else "All CVE IDs valid",
            details={"invalid_count": result}
        )
    
    def check_no_orphan_packages(self) -> QualityCheckResult:
        """Placeholder - would check package registry."""
        return QualityCheckResult(
            check_name="no_orphan_packages",
            passed=True,
            message="Check skipped (no package registry in prototype)"
        )
    
    def check_stalled_cves(self) -> QualityCheckResult:
        """Check for CVEs stuck in non-final state."""
        conn = self.db.connect()
        result = conn.execute("""
            SELECT count(*) FROM advisory_state_history
            WHERE is_current = true 
              AND state_type = 'non_final'
              AND effective_from < current_timestamp - interval '90 days'
        """).fetchone()[0]
        
        return QualityCheckResult(
            check_name="stalled_cves",
            passed=result < 10,  # Warning threshold
            message=f"{result} CVEs stalled >90 days" if result > 0 else "No stalled CVEs",
            details={"stalled_count": result}
        )
```

### Step 6.3: observability/reporter.py

```python
"""
Generate human-readable run reports.
"""
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path
from tabulate import tabulate

from .metrics import RunMetrics
from .quality_checks import QualityCheckResult

class RunReporter:
    """Generates run reports in Markdown format."""
    
    def generate_report(
        self, 
        metrics: RunMetrics, 
        quality_results: List[QualityCheckResult]
    ) -> str:
        """Generate full run report."""
        lines = []
        
        # Header
        lines.append("# Pipeline Run Report")
        lines.append(f"**Run ID:** {metrics.run_id}")
        lines.append(f"**Started:** {metrics.started_at.isoformat()}")
        if metrics.completed_at:
            duration = (metrics.completed_at - metrics.started_at).total_seconds()
            lines.append(f"**Duration:** {duration:.1f} seconds")
        lines.append("")
        
        # Summary table
        lines.append("## Summary")
        summary_data = [
            ["Total Advisories", metrics.advisories_total],
            ["Processed", metrics.advisories_processed],
            ["State Changes", metrics.state_changes],
            ["Errors", metrics.errors],
        ]
        lines.append(tabulate(summary_data, headers=["Metric", "Value"], tablefmt="github"))
        lines.append("")
        
        # State distribution
        if metrics.state_counts:
            lines.append("## State Distribution")
            state_data = [[k, v] for k, v in sorted(metrics.state_counts.items())]
            lines.append(tabulate(state_data, headers=["State", "Count"], tablefmt="github"))
            lines.append("")
        
        # Transitions
        if metrics.transitions:
            lines.append("## State Transitions")
            trans_data = [[f"{k[0]} → {k[1]}", v] for k, v in metrics.transitions.items()]
            lines.append(tabulate(trans_data, headers=["Transition", "Count"], tablefmt="github"))
            lines.append("")
        
        # Rules fired
        if metrics.rules_fired:
            lines.append("## Rules Fired")
            rules_data = [[k, v] for k, v in sorted(metrics.rules_fired.items())]
            lines.append(tabulate(rules_data, headers=["Rule", "Count"], tablefmt="github"))
            lines.append("")
        
        # Quality checks
        lines.append("## Data Quality Checks")
        quality_data = []
        for qr in quality_results:
            status = "✓" if qr.passed else "✗"
            quality_data.append([status, qr.check_name, qr.message])
        lines.append(tabulate(quality_data, headers=["Status", "Check", "Details"], tablefmt="github"))
        lines.append("")
        
        # Source health
        if metrics.source_health:
            lines.append("## Source Health")
            health_data = []
            for source, health in metrics.source_health.items():
                status = "✓" if health.get("healthy", False) else "✗"
                records = health.get("records", 0)
                health_data.append([status, source, records])
            lines.append(tabulate(health_data, headers=["Status", "Source", "Records"], tablefmt="github"))
            lines.append("")
        
        return "\n".join(lines)
    
    def save_report(self, report: str, output_dir: Path):
        """Save report to file."""
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filepath = output_dir / f"run_report_{timestamp}.md"
        filepath.write_text(report)
        return filepath
```

---

## Phase 7: Main Orchestrator

### Step 7.1: run_pipeline.py

```python
#!/usr/bin/env python3
"""
Main pipeline orchestrator.
Coordinates ingestion, dbt runs, and state management.
"""
import os
import sys
import json
import yaml
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from storage.database import Database
from storage.loader import SourceLoader
from storage.scd2_manager import SCD2Manager, AdvisoryState
from ingestion.echo_data_adapter import EchoDataAdapter
from ingestion.echo_csv_adapter import EchoCsvAdapter
from ingestion.nvd_adapter import NvdAdapter
from ingestion.osv_adapter import OsvAdapter
from observability.metrics import RunMetrics
from observability.quality_checks import QualityChecker
from observability.reporter import RunReporter

class AdvisoryPipeline:
    """
    Main pipeline orchestrator.
    
    Flow:
    1. Initialize run
    2. Ingest from all sources
    3. Run dbt models (staging → intermediate → marts)
    4. Apply SCD2 updates
    5. Run quality checks
    6. Generate reports
    7. Export outputs
    """
    
    def __init__(self, config_path: str = "config.yaml"):
        with open(config_path) as f:
            self.config = yaml.safe_load(f)
        
        self.db = Database(self.config["database"]["path"])
        self.loader = SourceLoader(self.db)
        self.scd2 = SCD2Manager(self.db)
        self.quality_checker = QualityChecker(self.db)
        self.reporter = RunReporter()
        
        # Initialize adapters
        self.adapters = {
            "echo_data": EchoDataAdapter(self.config["sources"]["echo_data"]),
            "echo_csv": EchoCsvAdapter(self.config["sources"]["echo_csv"]),
            "nvd": NvdAdapter(self.config["sources"]["nvd"]),
            "osv": OsvAdapter(self.config["sources"]["osv"]),
        }
    
    def run(self) -> RunMetrics:
        """Execute full pipeline run."""
        run_id = self.db.get_current_run_id()
        metrics = RunMetrics(run_id=run_id, started_at=datetime.utcnow())
        
        print(f"=== Pipeline Run: {run_id} ===")
        
        try:
            # 1. Initialize database schema
            print("Initializing database...")
            self.db.initialize_schema()
            
            # 2. Ingest from all sources
            print("Ingesting from sources...")
            self._ingest_all(run_id, metrics)
            
            # 3. Run dbt models
            print("Running dbt models...")
            self._run_dbt(run_id)
            
            # 4. Apply SCD2 updates
            print("Applying SCD2 updates...")
            self._apply_scd2_updates(run_id, metrics)
            
            # 5. Run quality checks
            print("Running quality checks...")
            quality_results = self.quality_checker.run_all_checks()
            
            # 6. Generate and save report
            print("Generating report...")
            self._finalize_metrics(metrics)
            report = self.reporter.generate_report(metrics, quality_results)
            report_path = self.reporter.save_report(report, Path("output"))
            print(f"Report saved to: {report_path}")
            
            # 7. Export current state to JSON
            print("Exporting advisory_current.json...")
            self._export_current_state()
            
            metrics.completed_at = datetime.utcnow()
            print(f"=== Run Complete: {metrics.state_changes} state changes ===")
            
        except Exception as e:
            metrics.record_error(str(e))
            print(f"ERROR: {e}")
            raise
        
        return metrics
    
    def _ingest_all(self, run_id: str, metrics: RunMetrics):
        """Ingest from all sources."""
        for name, adapter in self.adapters.items():
            print(f"  Ingesting from {name}...")
            observations = adapter.fetch()
            
            # Load to appropriate table
            if name == "echo_data":
                self.loader.load_echo_advisories(observations, run_id)
            elif name == "echo_csv":
                self.loader.load_echo_csv(observations, run_id)
            elif name == "nvd":
                self.loader.load_nvd_observations(observations, run_id)
            elif name == "osv":
                self.loader.load_osv_observations(observations, run_id)
            
            # Record source health
            health = adapter.get_health()
            metrics.source_health[name] = {
                "healthy": health.is_healthy,
                "records": len(observations),
                "error": health.error_message
            }
            print(f"    Loaded {len(observations)} records")
    
    def _run_dbt(self, run_id: str):
        """Run dbt models."""
        dbt_dir = Path("dbt_project")
        
        # Set run ID as environment variable for dbt
        env = os.environ.copy()
        env["PIPELINE_RUN_ID"] = run_id
        
        # Run dbt
        result = subprocess.run(
            ["dbt", "run", "--profiles-dir", "."],
            cwd=dbt_dir,
            env=env,
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print(f"dbt stdout: {result.stdout}")
            print(f"dbt stderr: {result.stderr}")
            raise RuntimeError(f"dbt run failed: {result.stderr}")
        
        print("  dbt models completed successfully")
    
    def _apply_scd2_updates(self, run_id: str, metrics: RunMetrics):
        """Read dbt output and apply SCD2 updates."""
        conn = self.db.connect()
        
        # Read decisions from dbt mart
        decisions = conn.execute("""
            SELECT * FROM mart_advisory_current
        """).fetchall()
        
        columns = [desc[0] for desc in conn.description]
        
        for row in decisions:
            decision = dict(zip(columns, row))
            
            # Get previous state for transition tracking
            prev = self.scd2.get_current_state(decision["advisory_id"])
            prev_state = prev["state"] if prev else "unknown"
            
            # Create AdvisoryState
            new_state = AdvisoryState(
                advisory_id=decision["advisory_id"],
                cve_id=decision["cve_id"],
                package_name=decision["package_name"],
                state=decision["state"],
                state_type=decision["state_type"],
                fixed_version=decision.get("fixed_version"),
                confidence=decision["confidence"],
                explanation=decision["explanation"],
                reason_code=decision["reason_code"],
                evidence=json.loads(decision["evidence"]) if decision["evidence"] else {},
                decision_rule=decision["decision_rule"],
                contributing_sources=json.loads(decision["contributing_sources"]) if decision["contributing_sources"] else [],
                dissenting_sources=json.loads(decision["dissenting_sources"]) if decision["dissenting_sources"] else [],
                staleness_score=decision.get("staleness_score", 0.0)
            )
            
            # Apply SCD2 update
            changed = self.scd2.apply_state(new_state, run_id)
            
            if changed:
                metrics.record_transition(prev_state, new_state.state)
                metrics.record_rule_fired(decision["decision_rule"])
            
            metrics.advisories_processed += 1
        
        metrics.advisories_total = len(decisions)
    
    def _finalize_metrics(self, metrics: RunMetrics):
        """Calculate final metrics."""
        conn = self.db.connect()
        
        # Get state distribution
        results = conn.execute("""
            SELECT state, count(*) 
            FROM advisory_state_history 
            WHERE is_current = true
            GROUP BY state
        """).fetchall()
        
        metrics.state_counts = {row[0]: row[1] for row in results}
    
    def _export_current_state(self):
        """Export current advisory state to JSON."""
        conn = self.db.connect()
        
        results = conn.execute("""
            SELECT 
                advisory_id,
                cve_id,
                package_name,
                state,
                state_type,
                fixed_version,
                confidence,
                explanation,
                reason_code,
                contributing_sources,
                dissenting_sources,
                effective_from,
                run_id
            FROM advisory_state_history
            WHERE is_current = true
        """).fetchall()
        
        columns = [desc[0] for desc in conn.description]
        advisories = []
        
        for row in results:
            adv = dict(zip(columns, row))
            # Convert datetime to string
            if adv.get("effective_from"):
                adv["effective_from"] = adv["effective_from"].isoformat()
            # Parse JSON fields
            if adv.get("contributing_sources"):
                adv["contributing_sources"] = json.loads(adv["contributing_sources"])
            if adv.get("dissenting_sources"):
                adv["dissenting_sources"] = json.loads(adv["dissenting_sources"])
            advisories.append(adv)
        
        output = {
            "generated_at": datetime.utcnow().isoformat(),
            "advisory_count": len(advisories),
            "advisories": advisories
        }
        
        output_path = Path("output/advisory_current.json")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(output, f, indent=2)
        
        print(f"  Exported {len(advisories)} advisories to {output_path}")


if __name__ == "__main__":
    pipeline = AdvisoryPipeline()
    pipeline.run()
```

---

## Phase 8: Demo Script

### Step 8.1: demo.py

```python
#!/usr/bin/env python3
"""
Demonstration script showing pipeline evolution over multiple runs.
Simulates realistic scenarios with changing upstream data.
"""
import os
import sys
import json
import shutil
import csv
from pathlib import Path
from datetime import datetime
from time import sleep

sys.path.insert(0, str(Path(__file__).parent))

from run_pipeline import AdvisoryPipeline
from storage.database import Database

def setup_demo_data():
    """Create realistic demo data files."""
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)
    
    # Create sample Echo data.json
    echo_data = {
        "packages": {
            "example-package": {
                "advisories": [
                    {"cve": "CVE-2024-0001", "status": "open", "cvss_score": 7.5},
                    {"cve": "CVE-2024-0002", "status": "open", "cvss_score": 5.0},
                    {"cve": "CVE-2024-0003", "status": "open", "cvss_score": 9.8},
                ]
            },
            "another-package": {
                "advisories": [
                    {"cve": "CVE-2024-0004", "status": "open", "cvss_score": 6.5},
                    {"cve": "CVE-2024-0005", "status": "open", "cvss_score": 4.0},
                ]
            },
            "db-handler": {
                "advisories": [
                    {"cve": "CVE-2024-0003", "status": "open", "cvss_score": 9.8},
                ]
            },
            "parser-lib": {
                "advisories": [
                    {"cve": "CVE-2024-0004", "status": "open", "cvss_score": 6.5},
                ]
            }
        }
    }
    
    with open(data_dir / "echo_data.json", "w") as f:
        json.dump(echo_data, f, indent=2)
    
    print("Created demo Echo data.json")

def create_csv_run1():
    """Run 1: No CSV overrides."""
    csv_path = Path("data/echo_overrides.csv")
    # Empty or missing CSV
    if csv_path.exists():
        csv_path.unlink()
    print("Run 1: No CSV overrides")

def create_csv_run2():
    """Run 2: Add some CSV overrides."""
    csv_path = Path("data/echo_overrides.csv")
    
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "package_name", "cve_id", "status", "reason", "analyst", "updated_at"
        ])
        writer.writeheader()
        writer.writerow({
            "package_name": "example-package",
            "cve_id": "CVE-2024-0002",
            "status": "not_applicable",
            "reason": "Vulnerable code path not used in our build",
            "analyst": "security-team",
            "updated_at": datetime.utcnow().isoformat()
        })
    
    print("Run 2: Added 1 CSV override (CVE-2024-0002 not_applicable)")

def update_osv_run3():
    """Run 3: OSV shows more fixes."""
    mock_dir = Path("ingestion/mock_responses")
    
    osv_data = {
        "vulns": [
            {
                "id": "GHSA-0001-0001-0001",
                "aliases": ["CVE-2024-0001"],
                "summary": "Buffer overflow in example package",
                "affected": [{
                    "package": {"name": "example-package", "ecosystem": "PyPI"},
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]
                    }]
                }],
                "references": [{"type": "FIX", "url": "https://github.com/example/commit/abc"}]
            },
            {
                "id": "GHSA-0002-0002-0002",
                "aliases": ["CVE-2024-0003"],
                "summary": "SQL injection",
                "affected": [{
                    "package": {"name": "db-handler", "ecosystem": "npm"},
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]
                    }]
                }],
                "references": [{"type": "FIX", "url": "https://github.com/example/commit/def"}]
            },
            # NEW: CVE-2024-0004 now has a fix
            {
                "id": "GHSA-0003-0003-0003",
                "aliases": ["CVE-2024-0004"],
                "summary": "Denial of service",
                "affected": [{
                    "package": {"name": "parser-lib", "ecosystem": "PyPI"},
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "3.0.0"}]  # NOW FIXED
                    }]
                }],
                "references": [{"type": "FIX", "url": "https://github.com/example/commit/ghi"}]
            }
        ]
    }
    
    with open(mock_dir / "osv_responses.json", "w") as f:
        json.dump(osv_data, f, indent=2)
    
    print("Run 3: OSV now shows fix for CVE-2024-0004")

def show_state_history(db: Database, cve_id: str):
    """Display state history for a CVE."""
    conn = db.connect()
    results = conn.execute("""
        SELECT 
            cve_id,
            state,
            reason_code,
            effective_from,
            effective_to,
            run_id
        FROM advisory_state_history
        WHERE cve_id = ?
        ORDER BY effective_from
    """, [cve_id]).fetchall()
    
    print(f"\n  History for {cve_id}:")
    for row in results:
        to_time = row[4] if row[4] else "current"
        print(f"    {row[1]:20} | {row[2]:15} | {row[5]} | {str(row[3])[:19]} → {str(to_time)[:19]}")

def main():
    """Run the demo."""
    print("=" * 60)
    print("CVE Advisory Pipeline Demo")
    print("=" * 60)
    
    # Clean previous run
    db_path = Path("advisory_pipeline.duckdb")
    if db_path.exists():
        db_path.unlink()
    
    output_dir = Path("output")
    if output_dir.exists():
        shutil.rmtree(output_dir)
    
    # Setup
    setup_demo_data()
    
    # === RUN 1 ===
    print("\n" + "=" * 60)
    print("RUN 1: Initial Load (no overrides)")
    print("=" * 60)
    create_csv_run1()
    
    pipeline = AdvisoryPipeline()
    metrics1 = pipeline.run()
    
    print(f"\nRun 1 Results:")
    print(f"  State distribution: {metrics1.state_counts}")
    
    sleep(1)  # Ensure different timestamps
    
    # === RUN 2 ===
    print("\n" + "=" * 60)
    print("RUN 2: CSV Override Added")
    print("=" * 60)
    create_csv_run2()
    
    metrics2 = pipeline.run()
    
    print(f"\nRun 2 Results:")
    print(f"  State changes: {metrics2.state_changes}")
    print(f"  Transitions: {dict(metrics2.transitions)}")
    
    sleep(1)
    
    # === RUN 3 ===
    print("\n" + "=" * 60)
    print("RUN 3: Upstream Fix Available")
    print("=" * 60)
    update_osv_run3()
    
    metrics3 = pipeline.run()
    
    print(f"\nRun 3 Results:")
    print(f"  State changes: {metrics3.state_changes}")
    print(f"  Transitions: {dict(metrics3.transitions)}")
    
    # Show state evolution
    print("\n" + "=" * 60)
    print("STATE EVOLUTION")
    print("=" * 60)
    
    db = Database("advisory_pipeline.duckdb")
    show_state_history(db, "CVE-2024-0001")
    show_state_history(db, "CVE-2024-0002")
    show_state_history(db, "CVE-2024-0004")
    
    # Final state
    print("\n" + "=" * 60)
    print("FINAL STATE SUMMARY")
    print("=" * 60)
    print(f"\n  {metrics3.state_counts}")
    
    print("\n" + "=" * 60)
    print("Demo Complete!")
    print("=" * 60)
    print("\nOutputs:")
    print("  - output/advisory_current.json")
    print("  - output/run_report_*.md (one per run)")
    print("  - advisory_pipeline.duckdb (full history)")

if __name__ == "__main__":
    main()
```

---

## Phase 9: Tests

### Step 9.1: tests/test_rules.py

```python
"""
Test decision rule logic.
"""
import pytest
from decisioning.rules import RULES, get_rules_sorted

def test_rules_sorted_by_priority():
    """Rules should be sorted by priority ascending."""
    rules = get_rules_sorted()
    priorities = [r.priority for r in rules]
    assert priorities == sorted(priorities)

def test_csv_override_rule():
    """CSV override should trigger on not_applicable status."""
    rule = next(r for r in RULES if r.id == "R0")
    
    # Should match
    assert rule.condition({"override_status": "not_applicable"}) == True
    
    # Should not match
    assert rule.condition({"override_status": None}) == False
    assert rule.condition({}) == False

def test_upstream_fix_rule():
    """Upstream fix requires both fix_available and fixed_version."""
    rule = next(r for r in RULES if r.id == "R2")
    
    # Should match
    assert rule.condition({"fix_available": True, "fixed_version": "1.0.0"}) == True
    
    # Should not match (missing version)
    assert rule.condition({"fix_available": True, "fixed_version": None}) == False
    assert rule.condition({"fix_available": True}) == False
    
    # Should not match (no fix)
    assert rule.condition({"fix_available": False, "fixed_version": "1.0.0"}) == False

def test_default_rule_always_matches():
    """Default rule should always match."""
    rule = next(r for r in RULES if r.id == "R6")
    assert rule.condition({}) == True
    assert rule.condition({"anything": "value"}) == True
```

### Step 9.2: tests/test_scd2.py

```python
"""
Test SCD2 state management.
"""
import pytest
from datetime import datetime, timedelta
from storage.database import Database
from storage.scd2_manager import SCD2Manager, AdvisoryState

@pytest.fixture
def db():
    """Create test database."""
    database = Database(":memory:")
    database.initialize_schema()
    return database

@pytest.fixture
def scd2(db):
    """Create SCD2 manager."""
    return SCD2Manager(db)

def test_initial_state_creates_record(scd2):
    """First state for advisory should create record."""
    state = AdvisoryState(
        advisory_id="test:CVE-2024-0001",
        cve_id="CVE-2024-0001",
        package_name="test",
        state="pending_upstream",
        state_type="non_final",
        fixed_version=None,
        confidence="low",
        explanation="Test explanation",
        reason_code="AWAITING_FIX",
        evidence={},
        decision_rule="R6:pending_upstream",
        contributing_sources=["osv"],
        dissenting_sources=[],
        staleness_score=0.0
    )
    
    changed = scd2.apply_state(state, "run_001")
    assert changed == True
    
    current = scd2.get_current_state("test:CVE-2024-0001")
    assert current is not None
    assert current["state"] == "pending_upstream"
    assert current["is_current"] == True

def test_state_change_creates_new_record(scd2):
    """State change should create new record and close old."""
    # Initial state
    state1 = AdvisoryState(
        advisory_id="test:CVE-2024-0001",
        cve_id="CVE-2024-0001",
        package_name="test",
        state="pending_upstream",
        state_type="non_final",
        fixed_version=None,
        confidence="low",
        explanation="Waiting for fix",
        reason_code="AWAITING_FIX",
        evidence={},
        decision_rule="R6",
        contributing_sources=[],
        dissenting_sources=[],
        staleness_score=0.0
    )
    scd2.apply_state(state1, "run_001")
    
    # State change
    state2 = AdvisoryState(
        advisory_id="test:CVE-2024-0001",
        cve_id="CVE-2024-0001",
        package_name="test",
        state="fixed",
        state_type="final",
        fixed_version="1.0.0",
        confidence="high",
        explanation="Fixed in 1.0.0",
        reason_code="UPSTREAM_FIX",
        evidence={"fixed_version": "1.0.0"},
        decision_rule="R2",
        contributing_sources=["osv"],
        dissenting_sources=[],
        staleness_score=0.0
    )
    changed = scd2.apply_state(state2, "run_002")
    
    assert changed == True
    
    # Check history
    history = scd2.get_history("test:CVE-2024-0001")
    assert len(history) == 2
    
    # Old record should be closed
    assert history[0]["is_current"] == False
    assert history[0]["effective_to"] is not None
    
    # New record should be current
    assert history[1]["is_current"] == True
    assert history[1]["effective_to"] is None

def test_no_change_no_new_record(scd2):
    """Same state should not create new record."""
    state = AdvisoryState(
        advisory_id="test:CVE-2024-0001",
        cve_id="CVE-2024-0001",
        package_name="test",
        state="pending_upstream",
        state_type="non_final",
        fixed_version=None,
        confidence="low",
        explanation="Waiting",
        reason_code="AWAITING_FIX",
        evidence={},
        decision_rule="R6",
        contributing_sources=[],
        dissenting_sources=[],
        staleness_score=0.0
    )
    
    scd2.apply_state(state, "run_001")
    changed = scd2.apply_state(state, "run_002")
    
    assert changed == False
    
    history = scd2.get_history("test:CVE-2024-0001")
    assert len(history) == 1
```

---

## Phase 10: README

### Step 10.1: README.md

```markdown
# CVE Advisory Pipeline Prototype

A production-like vulnerability advisory enrichment pipeline demonstrating:
- Multi-source ingestion with conflict resolution
- Deterministic rule engine with full explainability  
- SCD Type 2 state history for audit trails
- dbt-based transformations
- Comprehensive observability

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Install dbt packages
cd dbt_project && dbt deps && cd ..

# Run the demo (3 runs showing pipeline evolution)
python demo.py
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    INGESTION LAYER                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │Echo Data │ │Echo CSV  │ │   NVD    │ │   OSV    │       │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘       │
│       └────────────┴────────────┴────────────┘             │
└───────────────────────────┬─────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  TRANSFORMATION LAYER (dbt)                 │
│  staging → intermediate → marts                             │
│  - Schema validation                                        │
│  - Identity resolution                                      │
│  - Signal aggregation                                       │
│  - Conflict resolution                                      │
│  - Decision engine (rule chain)                             │
└───────────────────────────┬─────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  STATE MANAGEMENT                           │
│  - SCD Type 2 history                                       │
│  - Point-in-time queries                                    │
│  - Transition validation                                    │
└───────────────────────────┬─────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                      OUTPUTS                                │
│  - advisory_current.json                                    │
│  - Run reports (Markdown)                                   │
│  - Metrics & quality checks                                 │
└─────────────────────────────────────────────────────────────┘
```

## Decision Rules

| Priority | Rule | Condition | State |
|----------|------|-----------|-------|
| 0 | CSV Override | Internal analyst marks not_applicable | not_applicable |
| 1 | NVD Rejected | NVD status = REJECTED | not_applicable |
| 2 | Upstream Fix | fix_available AND fixed_version | fixed |
| 5 | Under Investigation | No signals yet | under_investigation |
| 6 | Pending Upstream | Default | pending_upstream |

## Outputs

After running `demo.py`:

- `output/advisory_current.json` - Current advisory state with explanations
- `output/run_report_*.md` - Human-readable run reports
- `advisory_pipeline.duckdb` - Full state history (SCD2)

## Project Structure

```
advisory_pipeline/
├── ingestion/          # Source adapters
├── dbt_project/        # dbt models
├── decisioning/        # Rule engine
├── storage/            # Database & SCD2
├── observability/      # Metrics & reporting
├── tests/              # Unit tests
├── run_pipeline.py     # Main orchestrator
└── demo.py             # Multi-run demo
```

## Design Decisions

1. **dbt for transformations**: Declarative SQL, testable, documented
2. **DuckDB over SQLite**: Better dbt support, faster analytics
3. **SCD Type 2**: Full audit trail, point-in-time queries
4. **Deterministic rules**: Auditable, testable, explainable
5. **Source isolation**: Each source independent, graceful degradation

## Production Considerations

In production, this would use:
- Snowflake instead of DuckDB
- Airflow for orchestration
- Real API calls (with rate limiting, circuit breakers)
- Additional sources (Debian, GHSA, CISA KEV)
- More sophisticated conflict resolution
- LLM extraction for unstructured sources
```

---

## Phase 11: Bug Fixes

### Overview

Phase 8's demo enhancement revealed 4 critical architectural issues from Phase 7 that need to be addressed. These bugs prevent the pipeline from properly tracking state transitions and applying analyst overrides.

### Bug 1: SCD2 History Table Not Populated

**Issue**: The `advisory_state_history` table exists but remains empty after pipeline runs.

**Root Cause**: The Phase 7 pipeline uses dbt to write directly to `mart_advisory_current`, completely bypassing the `storage/scd2_manager.py` module. The SCD2 manager is never invoked.

**Impact**:
- No historical state tracking
- Cannot perform point-in-time queries
- Metrics show `state_changes = 0` even when CVEs change state
- No audit trail for compliance

**Evidence**:
```sql
SELECT COUNT(*) FROM advisory_state_history;
-- Returns: 0 (even after 3 demo runs)

SELECT COUNT(*) FROM main_marts.mart_advisory_current;
-- Returns: 40195 (populated correctly)
```

**Fix Required**:
1. Modify `run_pipeline.py` to read from `mart_advisory_current` after dbt runs
2. For each advisory, call `scd2_manager.track_advisory_state()`
3. This populates `advisory_state_history` with proper SCD2 semantics
4. Update observability layer to read from SCD2 table for state change metrics

**Files to Modify**:
- `run_pipeline.py` (add SCD2 tracking after dbt run)
- `observability/metrics_collector.py` (read from SCD2 table)

---

### Bug 2: State Change Detection Broken

**Issue**: Metrics show `state_changes = 0` even when CVEs visibly change state between runs.

**Root Cause**: The `metrics_collector.py` tries to compare current state against `advisory_state_history`, but that table is empty (see Bug 1). Without historical data, no changes can be detected.

**Impact**:
- Cannot measure pipeline effectiveness
- No visibility into which CVEs are being resolved
- Run reports show misleading "0 state changes" message

**Evidence**:
```
Run 3 output:
✓ 40195 advisories processed
✓ 0 state change(s) detected  # <- Wrong! CVE-2024-0004 changed to fixed

Demo shows CVE-2024-0004 changed:
Run 2: under_investigation
Run 3: fixed (from upstream patch)
```

**Fix Required**:
1. Fix Bug 1 first (populate SCD2 table)
2. Update `metrics_collector.collect_state_changes()` to handle empty history gracefully
3. Add test coverage for state transition detection

**Files to Modify**:
- `observability/metrics_collector.py`
- `tests/test_metrics_collector.py` (new file)

---

### Bug 3: CSV Override Not Working for NVD-Only CVEs

**Issue**: CVE-2024-0002 remains `pending_upstream` even after being added to `analysts_overrides.csv` with `not_applicable` status.

**Root Cause**: Package name mismatch in join logic. The dbt model `int_final_signals.sql` joins CSV overrides on both `cve_id` AND `package_name`:

```sql
LEFT JOIN {{ ref('stg_echo_csv_overrides') }} csv_override
  ON combined.cve_id = csv_override.cve_id
  AND combined.package_name = csv_override.package_name  # <- Problem!
```

When NVD provides a CVE without package information, `package_name = NULL`. The CSV override specifies a package name, so the join fails and the override is ignored.

**Impact**:
- Analyst overrides don't work for ~38k NVD-only CVEs
- Teams cannot triage CVEs that lack package context
- Defeats the purpose of human-in-the-loop workflow

**Evidence**:
```csv
# analysts_overrides.csv
CVE-2024-0002,example-package,not_applicable,Out of scope for our deployment

# NVD data
{"cve_id": "CVE-2024-0002", "package_name": null, ...}

# Result: No match, override ignored
```

**Fix Required**:
1. Change join to match on `cve_id` only (package_name is optional context)
2. Add test case for NVD-only CVE with CSV override
3. Update demo data to show this scenario working

**Files to Modify**:
- `dbt_project/models/intermediate/int_final_signals.sql`
- `tests/test_csv_overrides.py` (new file)

---

### Bug 4: Duplicate CVE Entries in mart_advisory_current

**Issue**: Each CVE appears 2+ times in `mart_advisory_current` with different states, one entry per source.

**Root Cause**: The pipeline creates separate observations for:
- NVD entry (package_name = NULL, state based on NVD signals)
- OSV entry (package_name = "example-package", state based on OSV signals)

Both entries persist to the final mart without deduplication or merging logic.

**Impact**:
- Confusing output (which state is "correct"?)
- Inflated advisory counts (40k unique CVEs appear as 60k+ entries)
- Difficult to answer "is CVE-X fixed?" (depends which row you query)
- Demo journey tracker shows multiple entries per CVE

**Evidence**:
```sql
SELECT cve_id, package_name, state
FROM main_marts.mart_advisory_current
WHERE cve_id = 'CVE-2024-0001';

# Returns:
# CVE-2024-0001, example-package, fixed
# CVE-2024-0001, NULL, pending_upstream
```

**Fix Required**:

**Option 1: Deduplication Logic** (Recommended)
- Merge entries for same CVE into single advisory
- Combine signals from all sources
- Use highest-priority state as final state
- Store contributing sources in array field

**Option 2: Granularity by Design**
- Keep separate entries (package-level granularity)
- Add view `mart_advisory_current_by_cve` that deduplicates
- Update demo to use deduplicated view
- Document that base mart is package-level, not CVE-level

**Files to Modify**:
- `dbt_project/models/marts/mart_advisory_current.sql` (add dedup logic)
- OR `dbt_project/models/marts/mart_advisory_current_by_cve.sql` (new view)
- `demo.py` (query deduplicated view)
- `observability/report_generator.py` (use correct counts)

---

### Implementation Priority

1. **Bug 1 (SCD2)** - Blocks Bug 2, foundational for audit trail
2. **Bug 2 (State Changes)** - Depends on Bug 1, needed for observability
3. **Bug 3 (CSV Override)** - Independent, breaks analyst workflow
4. **Bug 4 (Duplicates)** - Independent, affects data quality

### Acceptance Criteria

After Phase 11 is complete:

- [ ] `SELECT COUNT(*) FROM advisory_state_history` returns > 0 after demo run
- [ ] Demo shows `state_changes > 0` when CVE-2024-0004 transitions to fixed
- [ ] CVE-2024-0002 shows `not_applicable` state after CSV override in Run 2
- [ ] Each CVE appears exactly once in `mart_advisory_current` (or has clear dedup view)
- [ ] Demo journey tracker shows single entry per CVE
- [ ] All dbt tests pass
- [ ] New unit tests added for each bug fix

---

## Build Order Summary

1. **Phase 1**: Project setup (requirements, config)
2. **Phase 2**: Ingestion layer (adapters, mock data)
3. **Phase 3**: Storage layer (database, loader, SCD2)
4. **Phase 4**: dbt project (all models)
5. **Phase 5**: Decisioning layer (rules, state machine)
6. **Phase 6**: Observability (metrics, quality, reports)
7. **Phase 7**: Main orchestrator
8. **Phase 8**: Demo script
9. **Phase 9**: Tests
10. **Phase 10**: README
11. **Phase 11**: Bug fixes (SCD2, state changes, CSV overrides, deduplication)

## Validation Criteria

The prototype is complete when:

- [ ] `python demo.py` runs 3 iterations successfully
- [ ] State transitions visible in output reports
- [ ] `advisory_current.json` contains advisories with explanations
- [ ] SCD2 history shows state evolution over runs
- [ ] dbt tests pass (`dbt test`)
- [ ] Unit tests pass (`pytest tests/`)
- [ ] Each advisory has: state, explanation, evidence, contributing_sources
