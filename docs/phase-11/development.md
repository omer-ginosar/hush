# Development Guide

Agent-facing development reference for extending the CVE advisory pipeline.

## Development Workflow

### Setup

```bash
# Clone and setup
git clone <repo>
cd hush
python3 -m venv venv
source venv/bin/activate
cd advisory_pipeline
pip install -r requirements.txt
```

### Branch Strategy

```bash
# Create feature branch
git checkout -b feature/phase-N-component-name

# Make changes, test, commit
pytest tests/ -v
git add .
git commit -m "Phase N: Component description"

# Create PR
gh pr create --title "Phase N: Component" --body "$(cat <<'EOF'
## Summary
- Deliverable 1
- Deliverable 2

## Test plan
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual verification

🤖 Generated with Claude Code
EOF
)"
```

## Code Organization

### Module Structure

```
advisory_pipeline/
├── component_name/
│   ├── __init__.py          # Clean exports only
│   ├── core_module.py       # Main implementation
│   ├── readme.md            # Component documentation
│   └── examples/            # Usage examples (if needed)
└── tests/
    └── test_component.py    # Comprehensive tests
```

### Naming Conventions

- **Files**: `snake_case.py`
- **Classes**: `PascalCase`
- **Functions**: `snake_case()`
- **Constants**: `UPPER_SNAKE_CASE`
- **Private**: `_leading_underscore()`

### Code Style

```python
"""Module docstring: what this module does."""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass

@dataclass
class ExampleModel:
    """Clear, single-line description."""
    field_name: str
    optional_field: Optional[int] = None

class ExampleClass:
    """What this class does and why it exists."""

    def public_method(self, param: str) -> Dict[str, Any]:
        """What this method does.

        Args:
            param: What this parameter means

        Returns:
            What gets returned
        """
        # Implementation
        pass

    def _private_helper(self):
        """Internal helper - no external guarantees."""
        pass
```

**Guidelines:**
- Type hints on all function signatures
- Docstrings on all public classes/functions
- Single responsibility per function
- Minimal comments (code should be self-documenting)
- Only comment the "why", not the "what"

## Testing Strategy

### Test Structure (AAA Pattern)

```python
def test_specific_behavior():
    # Arrange: Setup test data and dependencies
    adapter = EchoDataAdapter(config)

    # Act: Execute the behavior being tested
    observations = adapter.fetch()

    # Assert: Verify expected outcomes
    assert len(observations) > 0
    assert all(obs.source_id == 'echo_data' for obs in observations)
```

### Test Organization

- **Unit tests**: Test single components in isolation
- **Integration tests**: Test component interactions
- **Fixtures**: Reusable test data in `conftest.py`

```python
# tests/conftest.py
import pytest

@pytest.fixture
def temp_database():
    """Temporary in-memory database."""
    db = Database(":memory:")
    db.initialize_schema()
    yield db
    db.close()
```

### Running Tests

```bash
# Fast unit tests during development
pytest tests/test_rules.py -v

# Integration tests before commit
pytest tests/test_integration.py -v

# Full suite before PR
pytest tests/ -v --cov=advisory_pipeline

# Specific test
pytest tests/test_rules.py::test_csv_override_rule -v
```

## Adding New Components

### 1. Adding a New Data Source

**Files to modify:**
1. `ingestion/new_source_adapter.py` - Implement `BaseAdapter`
2. `config.yaml` - Add source configuration
3. `storage/loader.py` - Add `load_new_source()` method
4. `storage/database.py` - Add `raw_new_source` table
5. `dbt_project/models/staging/stg_new_source.sql` - Staging model
6. `tests/test_adapters.py` - Test suite

**Template:**
```python
# ingestion/new_source_adapter.py
from .base_adapter import BaseAdapter, SourceObservation

class NewSourceAdapter(BaseAdapter):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.source_id = "new_source"

    def fetch(self) -> List[SourceObservation]:
        # Fetch from source
        pass

    def normalize(self, raw_record: Dict) -> SourceObservation:
        # Transform to SourceObservation
        pass
```

### 2. Adding a New Decision Rule

**Files to modify:**
1. `decisioning/rules.py` - Implement `Rule` class
2. `config.yaml` - Add rule definition
3. `tests/test_decisioning_rules.py` - Add tests

**Template:**
```python
# decisioning/rules.py
class NewRule(Rule):
    def __init__(self):
        super().__init__(
            rule_id="R7",
            name="new_rule",
            priority=7,
            reason_code="NEW_REASON"
        )

    def evaluate(self, data: Dict[str, Any]) -> Optional[Decision]:
        if self._matches_condition(data):
            return Decision(
                state="new_state",
                state_type="final",
                confidence="high",
                reason_code=self.reason_code,
                # ... other fields
            )
        return None
```

### 3. Adding a New dbt Model

```sql
-- dbt_project/models/marts/mart_new_output.sql
-- Brief description of what this mart provides

{{ config(materialized='table') }}

with source_data as (
    select * from {{ ref('int_enriched_advisories') }}
),

transformed as (
    select
        -- columns
    from source_data
)

select * from transformed
```

### 4. Adding a New Quality Check

```python
# observability/quality_checks.py
def check_new_validation(self) -> QualityCheckResult:
    """Check that new invariant holds."""
    query = """
        SELECT COUNT(*) as invalid_count
        FROM mart_advisory_current
        WHERE <invalid_condition>
    """
    result = self.db.execute(query).fetchone()

    return QualityCheckResult(
        check_name="new_validation",
        passed=result[0] == 0,
        invalid_count=result[0],
        message="Description of what was checked"
    )
```

## Configuration Management

### config.yaml Structure

```yaml
# Data source definitions
sources:
  new_source:
    type: "api|json|csv"
    path: "path/to/data"
    # Source-specific config

# Rule definitions
rules:
  - id: "R7"
    name: "new_rule"
    priority: 7
    reason_code: "NEW_REASON"

# Explanation templates
explanation_templates:
  NEW_REASON: "Template with {placeholder} substitution."
```

**Guidelines:**
- Keep config declarative (what, not how)
- Use descriptive keys
- Document non-obvious values
- Externalize all business logic (rules, thresholds, templates)

## Database Schema Evolution

### Adding New Raw Table

```python
# storage/database.py - initialize_schema()
conn.execute("""
    CREATE TABLE IF NOT EXISTS raw_new_source (
        observation_id VARCHAR PRIMARY KEY,
        -- fields from SourceObservation
        run_id VARCHAR
    )
""")
```

### Adding Index

```python
conn.execute("""
    CREATE INDEX IF NOT EXISTS idx_table_column
    ON table_name(column_name)
""")
```

## dbt Development

### Model Layers

1. **Staging** (`models/staging/`) - Validation and cleaning
2. **Intermediate** (`models/intermediate/`) - Enrichment and joins
3. **Marts** (`models/marts/`) - Business-facing outputs

### dbt Commands

```bash
cd advisory_pipeline/dbt_project

# Compile models (syntax check)
dbt compile

# Run specific model
dbt run --select stg_echo_advisories

# Test data quality
dbt test

# Build all models
dbt build
```

### dbt Model Template

```sql
{{ config(materialized='view') }}  -- or 'table'

with source as (
    select * from {{ source('raw', 'raw_table_name') }}
    -- or {{ ref('upstream_model') }}
),

cleaned as (
    select
        column1,
        trim(column2) as column2,
        -- transformations
    from source
    where valid_record = true
)

select * from cleaned
```

## Interface Contracts

### Between Components

```
Ingestion → Storage
  Input:  Config dict
  Output: List[SourceObservation]

Storage → dbt
  Input:  List[SourceObservation]
  Output: Raw tables in DuckDB

dbt → Decisioning
  Input:  Raw tables
  Output: mart_advisory_current table

Decisioning → Output
  Input:  Enriched advisory data
  Output: Decision objects

Observability
  Input:  Database connection, run metadata
  Output: Metrics JSON, Markdown reports
```

### Data Models

**SourceObservation** (ingestion output):
```python
@dataclass
class SourceObservation:
    observation_id: str
    source_id: str
    cve_id: Optional[str]
    package_name: Optional[str]
    observed_at: datetime
    # ... normalized fields
```

**Decision** (rule engine output):
```python
@dataclass
class Decision:
    state: str
    state_type: str  # 'final' | 'non_final'
    confidence: str  # 'high' | 'medium' | 'low'
    reason_code: str
    explanation: str
    evidence: Dict[str, Any]
    # ... metadata
```

## Error Handling

### Adapter Errors

```python
def fetch(self) -> List[SourceObservation]:
    self._last_fetch = datetime.utcnow()
    try:
        # Fetch logic
        self._last_error = None
        return observations
    except Exception as e:
        self._last_error = str(e)
        return []  # Graceful degradation
```

### Rule Evaluation Errors

```python
try:
    decision = rule.evaluate(data)
except Exception as e:
    # Log but continue to next rule
    self._log_rule_error(rule, e)
    decision = None
```

**Philosophy**: Fail gracefully, log comprehensively, don't halt pipeline.

## Memory/Context Management

### Updating Implementation Status

After completing a phase, update [implementation-status.md](../implementation-status.md):

```markdown
### ✅ Phase N: Component Name (COMPLETE)

**Completed**: YYYY-MM-DD
**Branch**: `feature/phase-N-component`

**Deliverables**:
- ✓ Deliverable 1
- ✓ Deliverable 2

**Key Design Decisions**:
1. Decision 1 and rationale
2. Decision 2 and rationale

**Test Results**: X tests passing

**Interface Contract**:
- Input: What this component consumes
- Output: What this component produces

**Next Phase**: Phase N+1 description
```

### Component README Template

```markdown
# Component Name

Brief description of what this component does.

## Purpose

Why this component exists and what problem it solves.

## Usage

```python
from advisory_pipeline.component import MainClass

# Basic usage example
obj = MainClass(config)
result = obj.main_method(input)
```

## Components

### SubComponent1
What it does.

### SubComponent2
What it does.

## Interface

**Input**: Description of expected input
**Output**: Description of produced output
**Dependencies**: Other components this depends on

## Extension Points

How to extend this component for new use cases.
```

## Common Patterns

### Configuration Loading

```python
import yaml
from pathlib import Path

def load_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)
```

### Database Context Manager

```python
db = Database("pipeline.duckdb")
try:
    conn = db.connect()
    # Use connection
finally:
    db.close()
```

### Batch Processing

```python
def process_batch(items: List[Any], batch_size: int = 100):
    for i in range(0, len(items), batch_size):
        batch = items[i:i + batch_size]
        # Process batch
```

## Performance Considerations

1. **Use DuckDB bulk operations**: Avoid row-by-row inserts
2. **Let dbt handle transformations**: Don't replicate SQL in Python
3. **Cache adapter responses**: Avoid redundant API calls
4. **Index strategically**: Add indexes for join/filter columns

## Debugging

### Enable Verbose Logging

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Inspect Database State

```bash
duckdb advisory_pipeline.duckdb

# Show tables
.tables

# Inspect data
SELECT * FROM mart_advisory_current LIMIT 10;

# Count by state
SELECT state, COUNT(*) FROM mart_advisory_current GROUP BY state;

# Check SCD2 history
SELECT * FROM advisory_state_history WHERE is_current = true;
```

### Test Single Component

```bash
# Test adapter in isolation
python3 -c "
from advisory_pipeline.ingestion import EchoDataAdapter
import yaml

with open('config.yaml') as f:
    config = yaml.safe_load(f)

adapter = EchoDataAdapter(config['sources']['echo_data'])
obs = adapter.fetch()
print(f'Fetched {len(obs)} observations')
"
```

## Pre-Commit Checklist

- [ ] All tests pass: `pytest tests/ -v`
- [ ] Code follows style guide (type hints, docstrings)
- [ ] No unused imports or variables
- [ ] Error handling covers failure cases
- [ ] Documentation updated (README, docstrings)
- [ ] Implementation status updated (for new phases)
- [ ] Example usage provided (if public API changed)
- [ ] No secrets or hardcoded paths
- [ ] Commit message descriptive: "Phase N: What changed"

## Agent-Specific Notes

### When Starting a New Phase

1. Read [prototype-implementation-plan.md](../prototype-implementation-plan.md) for phase spec
2. Check [implementation-status.md](../implementation-status.md) for completed phases
3. Create feature branch: `git checkout -b feature/phase-N-name`
4. Implement minimal scope (avoid gold-plating)
5. Write tests before marking complete
6. Update implementation status
7. Create PR with clear description

### When Extending Existing Code

1. Read component README first
2. Check existing tests for usage examples
3. Maintain existing interfaces (backward compatibility)
4. Add tests for new behavior
5. Update component README if interface changed

### When in Doubt

- **Simplicity over cleverness**: Prefer boring, obvious code
- **Tests over comments**: Show usage through tests
- **Configuration over code**: Externalize business logic
- **Let tools do their job**: dbt for SQL, Python for orchestration

---

**For Human Reviewers**: See [readme.md](../../readme.md) for user-facing documentation
**For Implementation Plan**: See [prototype-implementation-plan.md](../prototype-implementation-plan.md)
**For Current Status**: See [implementation-status.md](../implementation-status.md)
