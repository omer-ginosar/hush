# How to Verify Phase 5 Is Working Correctly

## TL;DR - Quick Verification (30 seconds)

```bash
cd advisory_pipeline

# Run all unit tests (45 tests)
python3 -m pytest tests/test_decisioning_*.py -v

# Run validation suite (7 end-to-end tests)
python3 decisioning/validate.py
```

**Expected results:**
```
============================== 45 passed ==============================
🎉 ALL VALIDATION TESTS PASSED!
Total: 7/7 tests passed
```

If both pass, **Phase 5 is working correctly**. ✅

---

## What Each Validation Tests

### Unit Tests (45 tests)
Tests individual components in isolation:

1. **Rules** (12 tests) - Each rule's matching logic
2. **Engine** (7 tests) - Priority ordering, batch processing
3. **State Machine** (13 tests) - Transition validation, regression prevention
4. **Explainer** (13 tests) - Template rendering, data formatting

### Validation Suite (7 tests)
Tests realistic end-to-end scenarios:

1. **Rule Priority** - CSV override beats NVD beats OSV
2. **State Transitions** - Prevents final → non-final regressions
3. **Explanations** - Customer-facing text generated correctly
4. **Decision Flows** - 4 complete scenarios (fixed, rejected, investigating, pending)
5. **Batch Processing** - 10 advisories processed correctly
6. **Determinism** - 100 identical runs produce same result
7. **Error Handling** - Missing fields handled gracefully

---

## What This Tells You

### ✅ If All Tests Pass

The decisioning layer is **production-ready**:

- Rules evaluate correctly and in priority order
- State transitions are validated (no regressions)
- Decisions are deterministic and traceable
- Explanations are customer-facing
- Batch processing works at scale
- Error handling is robust

**You can confidently:**
- Integrate with Phase 6 (Orchestration)
- Connect to dbt mart outputs
- Write decisions to SCD2 storage
- Export to customer-facing JSON
- Deploy to production

### ❌ If Tests Fail

The failure message shows **exactly what's wrong**:

```bash
# Example failure
AssertionError: Expected state not_applicable, got fixed
  File "test_decisioning_rules.py", line 42, in test_csv_override
```

This tells you:
- Which component failed (rules, engine, state machine, explainer)
- Which specific behavior is broken
- What was expected vs what happened

**Fix the issue and re-run tests.**

---

## Manual Smoke Test

If you want to quickly verify by hand:

```bash
python3
```

```python
from decisioning import RuleEngine

engine = RuleEngine()

# Test: CSV override has highest priority
decision = engine.decide({
    'advisory_id': 'test:CVE-2024-0001',
    'override_status': 'not_applicable',
    'override_reason': 'False positive',
    'is_rejected': True,      # NVD also has an opinion
    'fix_available': True     # OSV also has an opinion
})

print(f"State: {decision.state}")           # Should be: not_applicable
print(f"Rule: {decision.evidence['applied_rule']}")  # Should be: R0
print(f"Explanation: {decision.explanation}")

# If you see:
# State: not_applicable
# Rule: R0
# Explanation: Marked as not applicable by Echo security team...
# Then it's working! ✅
```

---

## Integration Check

To verify Phase 5 integrates with the rest of the pipeline:

```python
from decisioning import RuleEngine, AdvisoryStateMachine

engine = RuleEngine()
sm = AdvisoryStateMachine()

# Simulate enriched data from dbt
dbt_output = {
    'advisory_id': 'urllib3:CVE-2024-1234',
    'cve_id': 'CVE-2024-1234',
    'package_name': 'urllib3',
    'fix_available': True,
    'fixed_version': '2.0.7',
    'contributing_sources': ['osv', 'nvd']
}

# 1. Make decision
decision = engine.decide(dbt_output)
print(f"Decision: {decision.state}")  # Should be: fixed

# 2. Validate state transition
current_state = None  # New advisory
is_valid, _ = sm.validate_transition(current_state, decision.state)
print(f"Transition valid: {is_valid}")  # Should be: True

# 3. Decision ready for SCD2 write
print(f"Ready to write: {decision.state} with confidence {decision.confidence}")
```

If this works, **integration is ready** for Phase 6. ✅

---

## Performance Check

Verify batch processing scales:

```python
from decisioning import RuleEngine
import time

engine = RuleEngine()

# Create 1000 advisories
batch = [
    {'advisory_id': f'pkg{i}:CVE-{i:06d}', 'fix_available': i % 2 == 0}
    for i in range(1000)
]

start = time.time()
decisions = engine.decide_batch(batch)
elapsed = time.time() - start

print(f"Processed {len(decisions)} advisories in {elapsed:.3f}s")
print(f"Rate: {len(decisions) / elapsed:.0f} decisions/sec")

# Expected: >100 decisions/sec
# Typical: 1000-5000 decisions/sec
```

If processing is fast, **performance is acceptable**. ✅

---

## CI/CD Integration

Add to your CI pipeline:

```yaml
# .github/workflows/test.yml
- name: Test Phase 5 Decisioning
  run: |
    cd advisory_pipeline
    python3 -m pytest tests/test_decisioning_*.py -v
    python3 decisioning/validate.py
```

This ensures Phase 5 stays correct as code evolves.

---

## Success Criteria Summary

| Check | Command | Expected Result |
|-------|---------|-----------------|
| Unit Tests | `pytest tests/test_decisioning_*.py` | 45 passed |
| Validation Suite | `python3 decisioning/validate.py` | 7/7 passed |
| Rule Priority | Manual test | R0 > R1 > R2 > R5 > R6 |
| State Transitions | Manual test | Final → non-final blocked |
| Batch Processing | Performance test | >100 decisions/sec |

If all checks pass, **Phase 5 is working correctly and ready for production**. ✅

---

## Troubleshooting

**Import errors:**
```bash
cd advisory_pipeline  # Make sure you're in the right directory
```

**Test failures:**
Read the error message - it shows exactly what's wrong and where.

**Unexpected behavior:**
Check the [full validation guide](PHASE5_VALIDATION_GUIDE.md) for detailed debugging steps.

---

## Next Steps

Once validated:

1. ✅ Merge PR to main
2. ✅ Integrate with Phase 6 (Orchestration)
3. ✅ Connect to dbt marts
4. ✅ Write decisions to SCD2 storage
5. ✅ Test end-to-end pipeline
