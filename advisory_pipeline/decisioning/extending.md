# Extending the Decisioning Layer

This guide shows how to add new rules and integrate new data sources.

## Quick Start: Adding a New Rule

### Example: Add "Distro Not Affected" Rule (R3)

**Step 1: Create the rule class**

Add to [rules.py](rules.py):

```python
class DistroNotAffectedRule(Rule):
    """R3: Distribution marks CVE as not affected."""

    def __init__(self):
        super().__init__("R3", 3, "DISTRO_NOT_AFFECTED")

    def evaluate(self, advisory_data: Dict[str, Any]) -> Optional[Decision]:
        # Check if distro data indicates not affected
        distro_status = advisory_data.get('distro_status')
        distro_notes = advisory_data.get('distro_notes')

        if distro_status == 'not_affected':
            return Decision(
                state='not_applicable',
                state_type='final',
                fixed_version=None,
                confidence='high',
                reason_code=self.reason_code,
                evidence={
                    'distro_status': distro_status,
                    'distro_notes': distro_notes,
                    'distro': advisory_data.get('distro', 'unknown')
                },
                explanation=self._build_explanation(advisory_data),
                contributing_sources=self._extract_sources(advisory_data),
                dissenting_sources=[]
            )

        return None

    def _build_explanation(self, advisory_data: Dict[str, Any]) -> str:
        distro = advisory_data.get('distro', 'unknown distribution')
        notes = advisory_data.get('distro_notes', 'Not specified')
        return f"Not affected in {distro}. Reason: {notes}."
```

**Step 2: Register the rule**

In [rules.py](rules.py), update `get_default_rules()`:

```python
def get_default_rules() -> List[Rule]:
    """Get the default rule chain in priority order."""
    return [
        CsvOverrideRule(),
        NvdRejectedRule(),
        UpstreamFixRule(),
        DistroNotAffectedRule(),  # ← Add here (priority 3)
        UnderInvestigationRule(),
        PendingUpstreamRule(),
    ]
```

**Step 3: Add explanation template**

In [config.yaml](../config.yaml):

```yaml
explanation_templates:
  # ... existing templates ...
  DISTRO_NOT_AFFECTED: "Not affected in {distro}. Reason: {distro_notes}."
```

**Step 4: Write tests**

In [tests/test_decisioning_rules.py](../tests/test_decisioning_rules.py):

```python
class TestDistroNotAffectedRule:
    """Test distro not affected rule (R3)."""

    def test_matches_when_distro_not_affected(self):
        rule = DistroNotAffectedRule()
        advisory_data = {
            'advisory_id': 'pkg:CVE-2024-0001',
            'distro_status': 'not_affected',
            'distro_notes': 'Vulnerable code not included in distro package',
            'distro': 'Ubuntu 22.04'
        }

        decision = rule.evaluate(advisory_data)

        assert decision is not None
        assert decision.state == 'not_applicable'
        assert decision.reason_code == 'DISTRO_NOT_AFFECTED'
        assert 'Ubuntu 22.04' in decision.explanation

    def test_no_match_when_distro_affected(self):
        rule = DistroNotAffectedRule()
        advisory_data = {
            'advisory_id': 'pkg:CVE-2024-0001',
            'distro_status': 'affected'
        }

        decision = rule.evaluate(advisory_data)
        assert decision is None
```

**Step 5: Verify**

```bash
pytest tests/test_decisioning_rules.py::TestDistroNotAffectedRule -v
```

---

## Adding a New Data Source

### Example: Add Ubuntu Security Tracker

**Step 1: Add dbt source**

In [dbt_project/models/sources.yml](../dbt_project/models/sources.yml):

```yaml
sources:
  - name: raw
    tables:
      # ... existing sources ...
      - name: raw_ubuntu_observations
        description: "Ubuntu Security Tracker data"
        columns:
          - name: observation_id
            tests: [unique, not_null]
          - name: cve_id
          - name: package_name
          - name: distro_status  # not_affected | affected | needs-triage
```

**Step 2: Create staging model**

Create [dbt_project/models/staging/stg_ubuntu_observations.sql](../dbt_project/models/staging/):

```sql
-- Staging model for Ubuntu Security Tracker

with source as (
    select * from {{ source('raw', 'raw_ubuntu_observations') }}
),

cleaned as (
    select
        observation_id,
        upper(trim(cve_id)) as cve_id,
        lower(trim(package_name)) as package_name,
        observed_at,
        raw_payload,
        lower(trim(distro_status)) as distro_status,
        distro_notes,
        distro_version,
        run_id

    from source
    where cve_id is not null
      and package_name is not null
)

select * from cleaned
```

**Step 3: Add to unified observations**

In [dbt_project/models/intermediate/int_source_observations.sql](../dbt_project/models/intermediate/int_source_observations.sql):

```sql
-- Add ubuntu CTE
ubuntu as (
    select
        observation_id,
        'ubuntu' as source_id,
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
        null::boolean as fix_available,
        null::varchar as fixed_version,
        distro_status,  -- ← New field
        distro_notes,   -- ← New field
        distro_version, -- ← New field
        notes,
        run_id
    from {{ ref('stg_ubuntu_observations') }}
),

-- Add to union
unioned as (
    select * from echo_advisories
    union all
    select * from echo_csv
    union all
    select * from nvd
    union all
    select * from osv
    union all
    select * from ubuntu  -- ← Add here
)
```

**Step 4: Update enrichment**

In [dbt_project/models/intermediate/int_enriched_advisories.sql](../dbt_project/models/intermediate/int_enriched_advisories.sql):

```sql
-- Aggregate Ubuntu signals
ubuntu_signals as (
    select
        coalesce(package_name, 'UNKNOWN') || ':' || cve_id as advisory_id,
        max(distro_status) as distro_status,
        max(distro_notes) as distro_notes,
        max(distro_version) as distro
    from observations
    where source_id = 'ubuntu'
    group by coalesce(package_name, 'UNKNOWN') || ':' || cve_id
),

-- Join in enriched CTE
enriched as (
    select
        ak.advisory_id,
        ak.cve_id,
        ak.package_name,

        -- Existing signals
        csv.override_status,
        nvd.nvd_rejection_status,
        osv.osv_fix_available,

        -- New Ubuntu signals
        ubuntu.distro_status,
        ubuntu.distro_notes,
        ubuntu.distro,

        -- ... rest of fields

    from advisory_keys ak
    left join csv_overrides csv on ak.advisory_id = csv.advisory_id
    left join nvd_signals nvd on ak.cve_id = nvd.cve_id
    left join osv_signals osv on ak.advisory_id = osv.advisory_id
    left join ubuntu_signals ubuntu on ak.advisory_id = ubuntu.advisory_id  -- ← Add join
)
```

**Step 5: Create Python adapter**

Create [ingestion/ubuntu_adapter.py](../ingestion/):

```python
"""
Ubuntu Security Tracker adapter.
"""
import json
import hashlib
import requests
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from .base_adapter import BaseAdapter, SourceObservation


class UbuntuAdapter(BaseAdapter):
    """
    Adapter for Ubuntu Security Tracker.

    Fetches CVE status from Ubuntu's security tracker API.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.source_id = "ubuntu"
        self.api_url = config.get('api_url', 'https://ubuntu.com/security/cves')
        self.distro_version = config.get('distro_version', '22.04')

    def fetch(self) -> List[SourceObservation]:
        """Fetch CVE data from Ubuntu tracker."""
        self._last_fetch = datetime.utcnow()

        try:
            # In production, call real API
            # response = requests.get(f"{self.api_url}/{cve_id}.json")

            # For prototype, return mock data
            observations = []
            # ... implementation

            self._last_error = None
            return observations

        except Exception as e:
            self._last_error = str(e)
            return []

    def normalize(self, raw_record: Dict[str, Any]) -> SourceObservation:
        """Transform Ubuntu data to normalized observation."""
        cve_id = raw_record.get('cve_id')
        package_name = raw_record.get('package')

        # Generate observation ID
        obs_id = hashlib.md5(
            f"{self.source_id}:{package_name}:{cve_id}".encode()
        ).hexdigest()[:16]

        # Extract status
        status_data = raw_record.get('status', {})
        distro_status = status_data.get(self.distro_version, {}).get('status')

        return SourceObservation(
            observation_id=obs_id,
            source_id=self.source_id,
            cve_id=cve_id,
            package_name=package_name,
            observed_at=datetime.utcnow(),
            source_updated_at=None,
            raw_payload=raw_record,
            notes=status_data.get('notes'),
            # Store distro-specific fields in raw_payload for now
        )
```

**Step 6: Update config**

In [config.yaml](../config.yaml):

```yaml
sources:
  # ... existing sources ...

  ubuntu:
    type: "api"
    api_url: "https://ubuntu.com/security/cves"
    distro_version: "22.04"
```

---

## Rule Template

Copy this template to add any new rule:

```python
class MyNewRule(Rule):
    """RX: Brief description of when this rule applies."""

    def __init__(self):
        # rule_id, priority, reason_code
        super().__init__("RX", X, "MY_REASON_CODE")

    def evaluate(self, advisory_data: Dict[str, Any]) -> Optional[Decision]:
        """
        Evaluate if this rule applies.

        Returns Decision if matched, None otherwise.
        """
        # 1. Extract relevant fields
        my_field = advisory_data.get('my_field')

        # 2. Check if rule applies
        if not self._rule_applies(my_field):
            return None

        # 3. Determine state
        state = self._determine_state(advisory_data)
        state_type = 'final' if state in ['fixed', 'not_applicable'] else 'non_final'

        # 4. Build evidence
        evidence = {
            'my_field': my_field,
            'additional_context': advisory_data.get('other_field')
        }

        # 5. Return decision
        return Decision(
            state=state,
            state_type=state_type,
            fixed_version=advisory_data.get('fixed_version') if state == 'fixed' else None,
            confidence=self._calculate_confidence(advisory_data),
            reason_code=self.reason_code,
            evidence=evidence,
            explanation=self._build_explanation(advisory_data),
            contributing_sources=self._extract_sources(advisory_data),
            dissenting_sources=[]
        )

    def _rule_applies(self, my_field: Any) -> bool:
        """Check if rule conditions are met."""
        # Your logic here
        return my_field is not None and my_field == 'expected_value'

    def _determine_state(self, advisory_data: Dict[str, Any]) -> str:
        """Determine the target state."""
        # Your logic here
        return 'fixed'  # or 'not_applicable', 'pending_upstream', etc.

    def _calculate_confidence(self, advisory_data: Dict[str, Any]) -> str:
        """Calculate confidence level."""
        # Your logic here
        return 'high'  # or 'medium', 'low'

    def _build_explanation(self, advisory_data: Dict[str, Any]) -> str:
        """Build human-readable explanation."""
        # Use template or build dynamically
        return f"Explanation based on {advisory_data.get('my_field')}"
```

---

## Common Patterns

### Pattern 1: Multi-Criteria Rule

```python
class ComplexRule(Rule):
    """Rule that checks multiple conditions."""

    def evaluate(self, advisory_data: Dict[str, Any]) -> Optional[Decision]:
        # All must be true
        if not (
            advisory_data.get('field1') == 'value1' and
            advisory_data.get('field2') > 5 and
            advisory_data.get('field3') in ['a', 'b', 'c']
        ):
            return None

        # Build decision...
```

### Pattern 2: Source Priority

```python
class SourcePriorityRule(Rule):
    """Rule that prefers certain sources."""

    def evaluate(self, advisory_data: Dict[str, Any]) -> Optional[Decision]:
        sources = advisory_data.get('contributing_sources', [])

        # Only apply if high-priority source present
        if 'trusted_source' not in sources:
            return None

        # Build decision...
```

### Pattern 3: Version Comparison

```python
from packaging import version

class VersionBasedRule(Rule):
    """Rule based on version comparisons."""

    def evaluate(self, advisory_data: Dict[str, Any]) -> Optional[Decision]:
        current = advisory_data.get('current_version')
        fixed = advisory_data.get('fixed_version')

        if current and fixed:
            try:
                if version.parse(current) >= version.parse(fixed):
                    return Decision(state='fixed', ...)
            except version.InvalidVersion:
                pass

        return None
```

### Pattern 4: Time-Based Rule

```python
from datetime import datetime, timedelta

class StalenessRule(Rule):
    """Rule based on time since last update."""

    def evaluate(self, advisory_data: Dict[str, Any]) -> Optional[Decision]:
        last_updated = advisory_data.get('last_updated')

        if last_updated:
            age = datetime.utcnow() - last_updated

            if age > timedelta(days=90):
                return Decision(
                    state='under_investigation',
                    confidence='low',
                    evidence={'staleness_days': age.days},
                    ...
                )

        return None
```

---

## Testing Your New Rule

Always write tests when adding a rule:

```python
def test_my_rule_matches():
    """Test that rule matches expected conditions."""
    rule = MyNewRule()

    advisory_data = {
        'advisory_id': 'test:CVE-2024-0001',
        'my_field': 'expected_value',
        'other_field': 'context'
    }

    decision = rule.evaluate(advisory_data)

    assert decision is not None
    assert decision.state == 'expected_state'
    assert decision.reason_code == 'MY_REASON_CODE'
    assert decision.confidence == 'high'

def test_my_rule_no_match():
    """Test that rule doesn't match when it shouldn't."""
    rule = MyNewRule()

    advisory_data = {
        'advisory_id': 'test:CVE-2024-0001',
        'my_field': 'wrong_value'
    }

    decision = rule.evaluate(advisory_data)
    assert decision is None
```

---

## Priority Guidelines

When choosing priority for your new rule:

- **0-2**: Override and authoritative sources (CSV, NVD, upstream fixes)
- **3-4**: Distribution/platform-specific signals
- **5-6**: Heuristics and defaults

**Example priority ordering:**
```
R0 (0): CSV Override          - Internal analyst decision
R1 (1): NVD Rejected          - Authoritative CVE database
R2 (2): Upstream Fix          - Fix available from source
R3 (3): Distro Not Affected   - Distribution says not affected
R4 (4): Distro Won't Fix      - Distribution won't fix
R5 (5): Under Investigation   - New CVE, no signals
R6 (6): Pending Upstream      - Default fallback
```

---

## Checklist: Adding a New Rule

- [ ] Create rule class in `rules.py`
- [ ] Implement `evaluate()` method
- [ ] Add to `get_default_rules()` with correct priority
- [ ] Add explanation template to `config.yaml`
- [ ] Write unit tests (match and no-match cases)
- [ ] Run tests: `pytest tests/test_decisioning_rules.py -v`
- [ ] Add to validation script scenarios (optional)
- [ ] Update documentation

---

## Need Help?

See:
- [rules.py](rules.py) - Existing rule implementations
- [readme.md](readme.md) - Architecture overview
- [../tests/test_decisioning_rules.py](../tests/test_decisioning_rules.py) - Test examples
