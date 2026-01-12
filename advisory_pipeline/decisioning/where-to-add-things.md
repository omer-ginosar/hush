# Where to Add Things - Visual Guide

Quick reference showing exactly which files to modify for common extension tasks.

## Adding a New Rule

```
advisory_pipeline/
├── decisioning/
│   ├── rules.py  ◄─ ADD YOUR RULE CLASS HERE
│   │   └── class MyNewRule(Rule):
│   │       └── def evaluate(...):
│   │
│   └── rules.py  ◄─ REGISTER IT HERE
│       └── def get_default_rules():
│           └── return [
│               ... existing rules ...
│               MyNewRule(),  ◄─ ADD THIS LINE
│               ...
│           ]
│
├── tests/
│   └── test_decisioning_rules.py  ◄─ ADD TESTS HERE
│       └── class TestMyNewRule:
│
└── config.yaml  ◄─ ADD EXPLANATION TEMPLATE HERE
    └── explanation_templates:
        └── MY_REASON_CODE: "..."
```

### File Checklist
- [ ] `decisioning/rules.py` - Add rule class
- [ ] `decisioning/rules.py` - Add to `get_default_rules()`
- [ ] `tests/test_decisioning_rules.py` - Add test class
- [ ] `config.yaml` - Add explanation template

---

## Adding a New Data Source

### Full Flow
```
Python Adapter → Raw DB Table → dbt Staging → dbt Enrichment → Python Rules
```

### Files to Modify

```
advisory_pipeline/
├── ingestion/
│   └── my_source_adapter.py  ◄─ CREATE NEW ADAPTER
│       └── class MySourceAdapter(BaseAdapter):
│
├── storage/
│   └── database.py  ◄─ ADD RAW TABLE SCHEMA
│       └── def initialize_schema():
│           └── CREATE TABLE raw_my_source (...)
│
├── dbt_project/
│   ├── models/
│   │   ├── sources.yml  ◄─ DECLARE SOURCE
│   │   │   └── - name: raw_my_source
│   │   │
│   │   ├── staging/
│   │   │   └── stg_my_source.sql  ◄─ CREATE STAGING MODEL
│   │   │
│   │   └── intermediate/
│   │       ├── int_source_observations.sql  ◄─ ADD TO UNION
│   │       │   └── union all
│   │       │       select * from my_source
│   │       │
│   │       └── int_enriched_advisories.sql  ◄─ ADD AGGREGATION
│   │           └── my_source_signals as (...)
│   │           └── left join my_source_signals
│
└── config.yaml  ◄─ ADD SOURCE CONFIG
    └── sources:
        └── my_source:
            type: "api"
            url: "..."
```

### File Checklist
- [ ] `ingestion/my_source_adapter.py` - Create adapter
- [ ] `storage/database.py` - Add raw table
- [ ] `dbt_project/models/sources.yml` - Declare source
- [ ] `dbt_project/models/staging/stg_my_source.sql` - Create staging
- [ ] `dbt_project/models/intermediate/int_source_observations.sql` - Add to union
- [ ] `dbt_project/models/intermediate/int_enriched_advisories.sql` - Add aggregation
- [ ] `config.yaml` - Add source config

---

## Example: Adding Ubuntu Security Tracker

### 1. Python Adapter
```python
# ingestion/ubuntu_adapter.py
class UbuntuAdapter(BaseAdapter):
    def __init__(self, config):
        self.source_id = "ubuntu"
        # ...
```

### 2. Raw Table
```python
# storage/database.py (in initialize_schema())
conn.execute("""
    CREATE TABLE IF NOT EXISTS raw_ubuntu_observations (
        observation_id VARCHAR PRIMARY KEY,
        cve_id VARCHAR,
        package_name VARCHAR,
        distro_status VARCHAR,
        distro_notes VARCHAR,
        run_id VARCHAR
    )
""")
```

### 3. dbt Source
```yaml
# dbt_project/models/sources.yml
sources:
  - name: raw
    tables:
      - name: raw_ubuntu_observations
        columns:
          - name: observation_id
            tests: [unique, not_null]
```

### 4. dbt Staging
```sql
-- dbt_project/models/staging/stg_ubuntu_observations.sql
with source as (
    select * from {{ source('raw', 'raw_ubuntu_observations') }}
),
cleaned as (
    select
        observation_id,
        cve_id,
        distro_status,
        distro_notes
    from source
)
select * from cleaned
```

### 5. Add to Observations Union
```sql
-- dbt_project/models/intermediate/int_source_observations.sql

ubuntu as (
    select
        observation_id,
        'ubuntu' as source_id,
        cve_id,
        package_name,
        distro_status,
        distro_notes,
        run_id
    from {{ ref('stg_ubuntu_observations') }}
),

unioned as (
    -- ... existing sources ...
    union all
    select * from ubuntu  ◄─ ADD THIS
)
```

### 6. Add to Enrichment
```sql
-- dbt_project/models/intermediate/int_enriched_advisories.sql

ubuntu_signals as (
    select
        advisory_id,
        max(distro_status) as distro_status,
        max(distro_notes) as distro_notes
    from observations
    where source_id = 'ubuntu'
    group by advisory_id
),

enriched as (
    select
        ak.*,
        ubuntu.distro_status,  ◄─ ADD FIELDS
        ubuntu.distro_notes
    from advisory_keys ak
    left join ubuntu_signals ubuntu on ak.advisory_id = ubuntu.advisory_id  ◄─ JOIN
)
```

### 7. Use in Rules
```python
# decisioning/rules.py
class DistroNotAffectedRule(Rule):
    def evaluate(self, advisory_data):
        # Now these fields are available!
        distro_status = advisory_data.get('distro_status')
        distro_notes = advisory_data.get('distro_notes')
        # ...
```

---

## Quick Templates

### Minimal Rule (Copy-Paste)
```python
# Add to decisioning/rules.py

class MyRule(Rule):
    def __init__(self):
        super().__init__("R7", 7, "MY_CODE")

    def evaluate(self, advisory_data):
        if advisory_data.get('my_field'):
            return Decision(
                state='fixed',
                state_type='final',
                fixed_version=None,
                confidence='high',
                reason_code=self.reason_code,
                evidence={'my_field': advisory_data.get('my_field')},
                explanation="Explanation here",
                contributing_sources=self._extract_sources(advisory_data),
                dissenting_sources=[]
            )
        return None
```

### Minimal Test (Copy-Paste)
```python
# Add to tests/test_decisioning_rules.py

class TestMyRule:
    def test_matches(self):
        rule = MyRule()
        decision = rule.evaluate({'advisory_id': 'test', 'my_field': 'value'})
        assert decision.state == 'fixed'

    def test_no_match(self):
        rule = MyRule()
        decision = rule.evaluate({'advisory_id': 'test'})
        assert decision is None
```

---

## Common Modifications

### Change Rule Priority
```python
# decisioning/rules.py - in get_default_rules()

# Move rule up (higher priority)
return [
    CsvOverrideRule(),
    MyRule(),  ◄─ Moved up to priority 1
    NvdRejectedRule(),
    ...
]
```

### Add Field to Enrichment
```sql
-- dbt_project/models/intermediate/int_enriched_advisories.sql

enriched as (
    select
        ak.*,
        my_new_field,  ◄─ ADD HERE
        existing_field
    from advisory_keys ak
)
```

### Add Custom State
```python
# decisioning/state_machine.py (optional)

class AdvisoryStateMachine:
    FINAL_STATES = {'fixed', 'not_applicable', 'wont_fix', 'my_new_state'}
```

Or configure in config.yaml:
```yaml
states:
  final:
    - fixed
    - not_applicable
    - wont_fix
    - my_new_state
```

---

## File Locations Reference

```
advisory_pipeline/
├── decisioning/           ◄─ Business logic (Python)
│   ├── rules.py          ◄─ Add rules here
│   ├── rule_engine.py    (No changes needed)
│   ├── state_machine.py  (Rarely modified)
│   └── explainer.py      (Rarely modified)
│
├── dbt_project/          ◄─ Data transformation (SQL)
│   └── models/
│       ├── staging/      ◄─ Add source staging models
│       └── intermediate/ ◄─ Add to enrichment
│
├── ingestion/            ◄─ Data ingestion (Python)
│   └── *_adapter.py      ◄─ Add source adapters
│
├── storage/              ◄─ Database (Python)
│   └── database.py       ◄─ Add raw tables
│
├── tests/                ◄─ Testing (Python)
│   └── test_decisioning_rules.py  ◄─ Add tests
│
└── config.yaml           ◄─ Configuration
    ├── sources:          ◄─ Add source configs
    └── explanation_templates:  ◄─ Add templates
```

---

## Don't Modify These (Unless You Know Why)

Usually **don't need to change**:
- `rule_engine.py` - Engine is generic
- `state_machine.py` - Validation logic is stable
- `explainer.py` - Template engine is generic
- `__init__.py` - Exports are stable

Only modify if:
- Adding new engine features
- Changing state transition rules
- Adding explanation features

---

## Getting Help

If you're unsure where something goes:

1. **Check examples**:
   - `examples/add_distro_rule.py` - Working example
   - Existing rules in `rules.py` - Pattern to follow

2. **Read guides**:
   - `quick-extension-guide.md` - 5-min quick start
   - `extending.md` - Detailed with examples

3. **Look at tests**:
   - `tests/test_decisioning_rules.py` - How to test rules
   - `tests/test_adapters.py` - How to test adapters

4. **Follow the data flow**:
   ```
   Source API → Adapter → Raw Table → Staging → Enrichment → Rules → Decision
   ```
