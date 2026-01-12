# Quick Extension Guide

## Add a New Rule in 5 Minutes

### Step 1: Copy the Template

In [rules.py](rules.py), find the `RULE TEMPLATE` section at the bottom and copy it.

### Step 2: Customize Your Rule

```python
class MyNewRule(Rule):
    """R7: Brief description."""

    def __init__(self):
        super().__init__("R7", 7, "MY_REASON_CODE")

    def evaluate(self, advisory_data: Dict[str, Any]) -> Optional[Decision]:
        # Your condition
        if advisory_data.get('my_field') == 'expected_value':
            return Decision(
                state='fixed',  # or 'not_applicable', 'pending_upstream'
                state_type='final',
                fixed_version=None,
                confidence='high',
                reason_code=self.reason_code,
                evidence={'my_field': advisory_data.get('my_field')},
                explanation="Your explanation here",
                contributing_sources=self._extract_sources(advisory_data),
                dissenting_sources=[]
            )
        return None
```

### Step 3: Register It

In `get_default_rules()`:

```python
def get_default_rules() -> List[Rule]:
    return [
        CsvOverrideRule(),
        NvdRejectedRule(),
        UpstreamFixRule(),
        MyNewRule(),  # ← Add here
        UnderInvestigationRule(),
        PendingUpstreamRule(),
    ]
```

### Step 4: Test It

```bash
python3 -c "
from decisioning import RuleEngine

engine = RuleEngine()
decision = engine.decide({
    'advisory_id': 'test',
    'my_field': 'expected_value'
})
print(f'State: {decision.state}')
print(f'Rule: {decision.evidence[\"applied_rule\"]}')
"
```

### Step 5: Add Unit Tests

In `tests/test_decisioning_rules.py`:

```python
class TestMyNewRule:
    def test_matches(self):
        rule = MyNewRule()
        decision = rule.evaluate({
            'advisory_id': 'test',
            'my_field': 'expected_value'
        })
        assert decision.state == 'fixed'

    def test_no_match(self):
        rule = MyNewRule()
        decision = rule.evaluate({'advisory_id': 'test'})
        assert decision is None
```

Run: `pytest tests/test_decisioning_rules.py::TestMyNewRule -v`

---

## Add a New Data Source

### Step 1: Create Adapter (Python)

In `ingestion/my_source_adapter.py`:

```python
from .base_adapter import BaseAdapter, SourceObservation

class MySourceAdapter(BaseAdapter):
    def __init__(self, config):
        super().__init__(config)
        self.source_id = "my_source"

    def fetch(self) -> List[SourceObservation]:
        # Fetch from API/file
        return observations

    def normalize(self, raw_record):
        # Transform to SourceObservation
        return SourceObservation(...)
```

### Step 2: Add dbt Staging Model

Create `dbt_project/models/staging/stg_my_source.sql`:

```sql
with source as (
    select * from {{ source('raw', 'raw_my_source') }}
),

cleaned as (
    select
        observation_id,
        cve_id,
        package_name,
        my_field,  -- Your custom fields
        run_id
    from source
)

select * from cleaned
```

### Step 3: Add to Enrichment

In `dbt_project/models/intermediate/int_enriched_advisories.sql`:

```sql
-- Add CTE for your source
my_source_signals as (
    select
        advisory_id,
        max(my_field) as my_field
    from observations
    where source_id = 'my_source'
    group by advisory_id
),

-- Join in enriched
enriched as (
    select
        ak.*,
        ms.my_field  -- Add your fields
    from advisory_keys ak
    left join my_source_signals ms on ak.advisory_id = ms.advisory_id
)
```

### Step 4: Use in Rules

Now `advisory_data.get('my_field')` will be available in rules!

---

## Common Patterns

### Pattern: Check Multiple Fields

```python
def evaluate(self, advisory_data):
    if (advisory_data.get('field1') == 'value1' and
        advisory_data.get('field2') > 10):
        return Decision(...)
    return None
```

### Pattern: Prefer Certain Sources

```python
def evaluate(self, advisory_data):
    sources = advisory_data.get('contributing_sources', [])
    if 'trusted_source' in sources:
        return Decision(...)
    return None
```

### Pattern: Version Comparison

```python
from packaging import version

def evaluate(self, advisory_data):
    current = advisory_data.get('current_version')
    fixed = advisory_data.get('fixed_version')

    if current and fixed:
        if version.parse(current) >= version.parse(fixed):
            return Decision(state='fixed', ...)
    return None
```

---

## Priority Guidelines

- **0-2**: Authoritative overrides (CSV, NVD, upstream)
- **3-4**: Platform-specific (distros, package managers)
- **5+**: Heuristics and defaults

---

## Checklist

- [ ] Create rule class
- [ ] Add to `get_default_rules()`
- [ ] Write tests
- [ ] Run tests: `pytest tests/test_decisioning_rules.py -v`
- [ ] Update config.yaml (explanation template)
- [ ] Document in extending.md

---

## Need More Details?

See:
- [extending.md](extending.md) - Full guide with examples
- [rules.py](rules.py) - Template at bottom of file
- [examples/add_distro_rule.py](examples/add_distro_rule.py) - Working example
