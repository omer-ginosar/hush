# Decisioning Layer

## Overview

The decisioning layer implements a deterministic, priority-ordered rule engine that evaluates enriched advisory data and produces explainable state decisions.

## Purpose

Transform enriched advisory observations into actionable states with:
- **Deterministic decisions**: Same input always produces same output
- **Explainability**: Every decision includes reason code, evidence, and human-readable explanation
- **Priority ordering**: Rules evaluated in strict priority order (0 = highest)
- **State validation**: Prevents invalid state transitions (e.g., final → non-final)

## Components

### 1. Rules (`rules.py`)

Individual rule implementations that evaluate advisory data.

**Current Rules (by priority):**
- **R0**: CSV Override - Internal analyst decisions (priority 0)
- **R1**: NVD Rejected - CVE rejected by NVD (priority 1)
- **R2**: Upstream Fix - Fix available from upstream (priority 2)
- **R5**: Under Investigation - New CVE with no signals (priority 5)
- **R6**: Pending Upstream - Default fallback (priority 6)

**Rule Interface:**
```python
class Rule(ABC):
    def evaluate(self, advisory_data: Dict[str, Any]) -> Optional[Decision]:
        """Return Decision if rule matches, None otherwise."""
        pass
```

**Decision Output:**
```python
@dataclass
class Decision:
    state: str                      # fixed | not_applicable | pending_upstream | etc.
    state_type: str                 # final | non_final
    fixed_version: Optional[str]
    confidence: str                 # high | medium | low
    reason_code: str                # CSV_OVERRIDE | UPSTREAM_FIX | etc.
    evidence: Dict[str, Any]        # Supporting data
    explanation: str                # Human-readable explanation
    contributing_sources: List[str] # Sources that contributed
    dissenting_sources: List[str]   # Sources that disagree
```

### 2. Rule Engine (`rule_engine.py`)

Orchestrates rule evaluation and produces decisions.

**Usage:**
```python
from advisory_pipeline.decisioning import RuleEngine

engine = RuleEngine()  # Uses default rules

# Single decision
decision = engine.decide(advisory_data)
print(f"State: {decision.state}, Reason: {decision.reason_code}")

# Batch processing
decisions = engine.decide_batch(advisory_list)

# Get explanation with trace
explanation = engine.explain_decision(advisory_data)
print(explanation['evaluation_trace'])
```

**Key Features:**
- First-match wins: Returns first rule that matches
- Error handling: Captures and logs rule evaluation errors
- Batch processing: Efficient processing of multiple advisories
- Explanation mode: Shows which rules were evaluated and why

### 3. State Machine (`state_machine.py`)

Validates state transitions to prevent invalid changes.

**State Model:**
- **Final states**: `fixed`, `not_applicable`, `wont_fix` (terminal)
- **Non-final states**: `pending_upstream`, `under_investigation`, `unknown` (can change)

**Transition Rules:**
- Non-final → Any: ✅ Allowed (new information)
- Final → Same final: ✅ Allowed (re-confirmation)
- Final → Different final: ✅ Allowed (rare but valid)
- Final → Non-final: ❌ Rejected (regression)

**Usage:**
```python
from advisory_pipeline.decisioning import AdvisoryStateMachine

sm = AdvisoryStateMachine()

# Validate transition
is_valid, reason = sm.validate_transition(
    current_state='pending_upstream',
    new_state='fixed'
)

if not is_valid:
    print(f"Invalid transition: {reason}")

# Get allowed transitions
allowed = sm.get_allowed_transitions('pending_upstream')
print(f"Can transition to: {allowed}")

# Describe transition
description = sm.describe_transition('fixed', 'pending_upstream')
print(f"Is regression: {description['is_regression']}")
```

### 4. Explainer (`explainer.py`)

Generates customer-facing explanations from decisions.

**Features:**
- Template-based: Uses configurable templates with variable substitution
- Default handling: Provides sensible defaults for missing values
- Date formatting: Formats timestamps to readable dates
- Context support: Can include decision metadata

**Usage:**
```python
from advisory_pipeline.decisioning import DecisionExplainer

explainer = DecisionExplainer()

# Simple explanation
explanation = explainer.explain(
    reason_code='UPSTREAM_FIX',
    evidence={'fixed_version': '2.1.0'},
    fixed_version='2.1.0'
)

# With metadata
result = explainer.explain_with_context(
    reason_code='UPSTREAM_FIX',
    evidence=evidence,
    fixed_version='2.1.0',
    include_metadata=True
)
print(result['explanation'])
print(result['metadata'])
```

## Integration

The decisioning layer is designed to be invoked after dbt transformations:

```
Raw Data → dbt Staging → dbt Intermediate → dbt Marts → Python Decisioning → SCD2 Storage
```

### Input

Expects enriched advisory data with these fields:
```python
{
    'advisory_id': str,           # Unique identifier
    'cve_id': str,                # CVE identifier
    'package_name': str,          # Package name

    # Enrichment signals
    'override_status': Optional[str],
    'override_reason': Optional[str],
    'is_rejected': bool,
    'fix_available': bool,
    'fixed_version': Optional[str],
    'has_signal': bool,

    # Metadata
    'contributing_sources': List[str],
    'source_count': int,
    'cvss_score': Optional[float],
    # ... other enrichment fields
}
```

### Output

Returns `Decision` objects that can be:
1. Written to SCD2 history tables
2. Exported to JSON for customer consumption
3. Used for reporting and metrics

## Extending

### Adding New Rules

1. Create rule class extending `Rule`:
```python
class MyNewRule(Rule):
    def __init__(self):
        super().__init__("R7", 7, "MY_REASON_CODE")

    def evaluate(self, advisory_data: Dict[str, Any]) -> Optional[Decision]:
        if advisory_data.get('my_condition'):
            return Decision(
                state='my_state',
                state_type='final',
                # ... other fields
            )
        return None
```

2. Add to default rules in `get_default_rules()`
3. Add explanation template to `config.yaml`

### Custom State Definitions

Override state classifications:
```python
custom_config = {
    'final': ['resolved', 'dismissed'],
    'non_final': ['open', 'investigating']
}
sm = AdvisoryStateMachine(custom_config)
```

### Custom Explanation Templates

Provide custom templates:
```python
custom_templates = {
    'MY_REASON_CODE': 'Custom explanation with {field1}.'
}
explainer = DecisionExplainer(templates=custom_templates)
```

## Testing

Comprehensive test suite in `tests/`:
- `test_decisioning_rules.py`: Individual rule logic
- `test_rule_engine.py`: Engine execution and prioritization
- `test_state_machine.py`: State transition validation
- `test_explainer.py`: Explanation generation

Run tests:
```bash
cd advisory_pipeline
pytest tests/test_decisioning_*.py -v
```

## Design Principles

1. **Single Responsibility**: Each rule does one thing
2. **Determinism**: No randomness, no timestamps in logic
3. **Explainability**: Every decision traceable to evidence
4. **Composability**: Rules are independent and reusable
5. **Fail-safe**: Always has fallback (R6)
6. **Immutability**: Decisions don't modify input data

## Known Limitations

1. **Rules R3 & R4 not implemented**: Require distribution-specific data not in prototype
2. **No time-based rules**: All decisions based on current state, no staleness-based transitions
3. **Simple conflict resolution**: Last-writer-wins for dissenting sources
4. **No ML/scoring**: Pure rule-based, no probabilistic decisions

## Future Enhancements

- Dynamic rule loading from configuration
- Rule performance metrics and monitoring
- A/B testing framework for rule changes
- Machine learning fallback for ambiguous cases
- Multi-criteria decision analysis for complex scenarios
