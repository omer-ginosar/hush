# Phase 5 Validation Guide

## How to Tell if Phase 5 is Working Correctly

This guide provides multiple approaches to validate that the decisioning layer has been implemented correctly and the system is functioning as expected.

## Quick Validation (30 seconds)

### 1. Run Unit Tests

The fastest way to verify correctness:

```bash
cd advisory_pipeline
python3 -m pytest tests/test_decisioning_*.py -v
```

**Expected output:**
```
============================== 45 passed ==============================
```

**What this validates:**
- ✅ All rules evaluate correctly
- ✅ Engine applies priority ordering
- ✅ State machine prevents invalid transitions
- ✅ Explanations generate properly
- ✅ Edge cases handled

**If tests fail:** Review the specific test failure. Each test is self-documenting and shows exactly what's expected.

### 2. Run Validation Script

Comprehensive end-to-end validation:

```bash
cd advisory_pipeline
python3 decisioning/validate.py
```

**Expected output:**
```
🎉 ALL VALIDATION TESTS PASSED!
Total: 7/7 tests passed
```

**What this validates:**
- ✅ Rule priority ordering (CSV override wins)
- ✅ State transition validation (regression prevention)
- ✅ Explanation generation from templates
- ✅ Realistic decision scenarios (4 complete flows)
- ✅ Batch processing (10 advisories)
- ✅ Determinism (100 identical decisions)
- ✅ Error handling (missing fields)

**If validation fails:** The script shows exactly which test failed and why.

## Detailed Validation (5 minutes)

### 3. Manual Decision Walkthrough

Test the decisioning layer interactively:

```python
# Start Python REPL
cd advisory_pipeline
python3

# Import components
from decisioning import RuleEngine, AdvisoryStateMachine, DecisionExplainer

# Create instances
engine = RuleEngine()
state_machine = AdvisoryStateMachine()
explainer = DecisionExplainer()

# Test 1: CSV Override (highest priority)
advisory = {
    'advisory_id': 'test:CVE-2024-0001',
    'override_status': 'not_applicable',
    'override_reason': 'False positive',
    'is_rejected': True,  # NVD also has opinion
    'fix_available': True  # OSV also has opinion
}

decision = engine.decide(advisory)
print(f"State: {decision.state}")  # Should be: not_applicable
print(f"Rule: {decision.evidence['applied_rule']}")  # Should be: R0
print(f"Confidence: {decision.confidence}")  # Should be: high
print(f"Explanation: {decision.explanation}")

# Test 2: Upstream Fix
advisory2 = {
    'advisory_id': 'pkg:CVE-2024-0002',
    'fix_available': True,
    'fixed_version': '2.0.0',
    'contributing_sources': ['osv']
}

decision2 = engine.decide(advisory2)
print(f"State: {decision2.state}")  # Should be: fixed
print(f"Rule: {decision2.evidence['applied_rule']}")  # Should be: R2
print(f"Version: {decision2.fixed_version}")  # Should be: 2.0.0

# Test 3: State Transition Validation
is_valid, reason = state_machine.validate_transition('fixed', 'pending_upstream')
print(f"Fixed → Pending: {is_valid}")  # Should be: False (regression)
print(f"Reason: {reason}")  # Should mention: regression

is_valid2, _ = state_machine.validate_transition('pending_upstream', 'fixed')
print(f"Pending → Fixed: {is_valid2}")  # Should be: True

# Test 4: Batch Processing
batch = [
    {'advisory_id': f'pkg{i}:CVE-{i}', 'fix_available': i % 2 == 0,
     'fixed_version': f'{i}.0' if i % 2 == 0 else None}
    for i in range(5)
]

decisions = engine.decide_batch(batch)
print(f"Processed: {len(decisions)}")  # Should be: 5
print(f"States: {[d.state for d in decisions]}")  # Should alternate fixed/pending
```

**Expected behavior:**
- Test 1: CSV override takes priority over all other signals
- Test 2: Upstream fix correctly identified with version
- Test 3: Regressions blocked, valid transitions allowed
- Test 4: Batch processing handles multiple advisories

### 4. Check Rule Priority Order

Verify that rules fire in correct priority:

```bash
cd advisory_pipeline
python3 -c "
from decisioning import get_default_rules

rules = get_default_rules()
for rule in rules:
    print(f'{rule.rule_id} (priority {rule.priority}): {rule.reason_code}')
"
```

**Expected output:**
```
R0 (priority 0): CSV_OVERRIDE
R1 (priority 1): NVD_REJECTED
R2 (priority 2): UPSTREAM_FIX
R5 (priority 5): NEW_CVE
R6 (priority 6): AWAITING_FIX
```

**What this validates:**
- ✅ All 5 rules present
- ✅ Correct priority ordering (0 is highest)
- ✅ Proper reason codes assigned

### 5. Test State Machine Logic

Verify all transition rules:

```python
from decisioning import AdvisoryStateMachine

sm = AdvisoryStateMachine()

# Test all non-final → any (should allow)
non_final = ['pending_upstream', 'under_investigation', 'unknown']
targets = ['fixed', 'not_applicable', 'wont_fix', 'pending_upstream']

print("Non-final → Any transitions:")
for current in non_final:
    for target in targets:
        valid, _ = sm.validate_transition(current, target)
        print(f"  {current} → {target}: {'✅' if valid else '❌'}")

# All should be ✅

# Test final → non-final (should reject)
final = ['fixed', 'not_applicable', 'wont_fix']
non_final_targets = ['pending_upstream', 'under_investigation', 'unknown']

print("\nFinal → Non-final transitions (regressions):")
for current in final:
    for target in non_final_targets:
        valid, _ = sm.validate_transition(current, target)
        print(f"  {current} → {target}: {'✅ ALLOWED' if valid else '❌ BLOCKED'}")

# All should be ❌ BLOCKED
```

### 6. Verify Explanation Templates

Check that all reason codes have explanations:

```python
from decisioning import DecisionExplainer

explainer = DecisionExplainer()

reason_codes = [
    'CSV_OVERRIDE',
    'NVD_REJECTED',
    'UPSTREAM_FIX',
    'NEW_CVE',
    'AWAITING_FIX'
]

print("Explanation templates:")
for code in reason_codes:
    evidence = {'fixed_version': '1.0.0', 'contributing_sources': ['osv']}
    explanation = explainer.explain(code, evidence, fixed_version='1.0.0')
    print(f"\n{code}:")
    print(f"  {explanation[:80]}...")
```

**Expected:** Each reason code should produce a sensible, customer-facing explanation.

## Integration Validation (End-to-End)

### 7. Simulate Full Pipeline Flow

Test how decisioning integrates with dbt output:

```python
from decisioning import RuleEngine, AdvisoryStateMachine
from storage.scd2_manager import SCD2Manager, AdvisoryState
from storage.database import Database

# Initialize components
engine = RuleEngine()
state_machine = AdvisoryStateMachine()
db = Database()
scd2 = SCD2Manager(db)

# Simulate enriched data from dbt
enriched_advisory = {
    'advisory_id': 'urllib3:CVE-2024-1234',
    'cve_id': 'CVE-2024-1234',
    'package_name': 'urllib3',
    'fix_available': True,
    'fixed_version': '2.0.7',
    'contributing_sources': ['osv', 'nvd'],
    'source_count': 2,
    'cvss_score': 7.5,
    'has_signal': True
}

# 1. Make decision
decision = engine.decide(enriched_advisory)
print(f"Decision: {decision.state}")
print(f"Confidence: {decision.confidence}")
print(f"Explanation: {decision.explanation}")

# 2. Get current state from SCD2
current = scd2.get_current_state(enriched_advisory['advisory_id'])
current_state = current['state'] if current else None

# 3. Validate transition
is_valid, reason = state_machine.validate_transition(current_state, decision.state)

if is_valid:
    print(f"✅ Transition valid: {current_state} → {decision.state}")

    # 4. Would write to SCD2 here
    # advisory_state = AdvisoryState(
    #     advisory_id=enriched_advisory['advisory_id'],
    #     cve_id=enriched_advisory['cve_id'],
    #     package_name=enriched_advisory['package_name'],
    #     state=decision.state,
    #     ...
    # )
    # scd2.apply_state(advisory_state, run_id)
else:
    print(f"❌ Transition rejected: {reason}")
```

**What this validates:**
- ✅ Decision making from enriched data
- ✅ Integration with SCD2 state management
- ✅ State transition validation before writes
- ✅ Complete data flow through pipeline

## Regression Testing

### 8. Test Against Known Scenarios

Use the realistic scenarios from validation script:

```bash
cd advisory_pipeline
python3 -c "
from decisioning import RuleEngine

engine = RuleEngine()

# Known scenario: Rejected CVE
advisory = {
    'advisory_id': 'pkg:CVE-2024-0002',
    'is_rejected': True,
    'nvd_rejection_status': 'rejected'
}

decision = engine.decide(advisory)
assert decision.state == 'not_applicable', f'Expected not_applicable, got {decision.state}'
assert decision.evidence['applied_rule'] == 'R1', f'Expected R1, got {decision.evidence[\"applied_rule\"]}'
print('✅ Rejected CVE scenario works correctly')
"
```

## Performance Validation

### 9. Batch Processing Performance

Verify batch processing scales:

```python
from decisioning import RuleEngine
import time

engine = RuleEngine()

# Create large batch
batch = [
    {
        'advisory_id': f'pkg{i}:CVE-{i:06d}',
        'fix_available': i % 3 == 0,
        'fixed_version': f'{i}.0' if i % 3 == 0 else None,
        'has_signal': True
    }
    for i in range(1000)
]

start = time.time()
decisions = engine.decide_batch(batch)
elapsed = time.time() - start

print(f"Processed {len(decisions)} advisories in {elapsed:.3f}s")
print(f"Rate: {len(decisions) / elapsed:.0f} decisions/sec")

# Expected: >100 decisions/sec (usually >1000/sec)
assert len(decisions) == 1000, "Should process all advisories"
assert elapsed < 5.0, "Should complete within 5 seconds"
```

## Troubleshooting

### Common Issues

**Tests fail with import errors:**
```bash
# Ensure you're in the right directory
cd advisory_pipeline

# Check Python path
python3 -c "import sys; print(sys.path)"
```

**State transitions unexpectedly rejected:**
- Check if current state is final
- Review state machine configuration
- Use `describe_transition()` for details:
  ```python
  description = sm.describe_transition('fixed', 'pending_upstream')
  print(description)
  ```

**Decisions not deterministic:**
- This should never happen - file a bug if it does
- Check if rule logic has any randomness
- Verify same input data used

**Explanations missing template variables:**
- Check that evidence dict contains required fields
- Review explainer's `_prepare_values()` method
- Missing values should use defaults, not error

## Success Criteria

Phase 5 is working correctly if:

1. ✅ **All 45 unit tests pass** (`pytest tests/test_decisioning_*.py`)
2. ✅ **All 7 validation tests pass** (`python3 decisioning/validate.py`)
3. ✅ **Rule priority ordering correct** (R0 > R1 > R2 > R5 > R6)
4. ✅ **State transitions validated** (final → non-final blocked)
5. ✅ **Decisions are deterministic** (same input → same output)
6. ✅ **Explanations are customer-facing** (clear, actionable language)
7. ✅ **Batch processing works** (handles 1000+ advisories)
8. ✅ **Error handling graceful** (missing fields don't crash)

## Next Steps After Validation

Once Phase 5 is validated:

1. **Phase 6 Integration**: Connect to orchestration layer
2. **SCD2 Writes**: Use decisions to update state history
3. **JSON Export**: Generate customer-facing advisory files
4. **Metrics Collection**: Track decision distributions
5. **Production Deployment**: Run on real advisory data

## Quick Reference

```bash
# Run all tests
cd advisory_pipeline
python3 -m pytest tests/test_decisioning_*.py -v

# Run validation suite
python3 decisioning/validate.py

# Interactive testing
python3
>>> from decisioning import RuleEngine
>>> engine = RuleEngine()
>>> decision = engine.decide({'advisory_id': 'test', 'fix_available': True, 'fixed_version': '1.0'})
>>> print(decision.state)
fixed

# Check rule priority
python3 -c "from decisioning import get_default_rules; [print(f'{r.rule_id}: priority {r.priority}') for r in get_default_rules()]"
```

## Continuous Validation

Add to CI/CD pipeline:

```bash
# In .github/workflows/test.yml or similar
- name: Test Phase 5 Decisioning
  run: |
    cd advisory_pipeline
    python3 -m pytest tests/test_decisioning_*.py -v
    python3 decisioning/validate.py
```

This ensures the decisioning layer remains correct as code evolves.
