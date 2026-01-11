#!/usr/bin/env python3
"""
Validation script for Phase 5: Decisioning Layer

This script demonstrates that the decisioning layer works correctly
by running realistic test scenarios and validating outputs.
"""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from decisioning import RuleEngine, AdvisoryStateMachine, DecisionExplainer
from decisioning.rules import get_default_rules


def validate_rule_priority():
    """Validate that rules are evaluated in correct priority order."""
    print("=" * 70)
    print("TEST 1: Rule Priority Validation")
    print("=" * 70)

    engine = RuleEngine()

    # Test case: CSV override should win over NVD rejected
    test_data = {
        'advisory_id': 'test-pkg:CVE-2024-0001',
        'override_status': 'not_applicable',
        'override_reason': 'False positive',
        'is_rejected': True,  # NVD also says rejected
        'fix_available': True,  # OSV says fixed
        'fixed_version': '1.0.0'
    }

    decision = engine.decide(test_data)

    print(f"Input: CSV override + NVD rejected + OSV fixed")
    print(f"Expected: CSV override wins (R0, priority 0)")
    print(f"Actual: {decision.evidence['applied_rule']} - {decision.reason_code}")
    print(f"State: {decision.state}")

    assert decision.evidence['applied_rule'] == 'R0', "CSV override should have highest priority"
    assert decision.reason_code == 'CSV_OVERRIDE', "Wrong reason code"
    print("✅ PASS: CSV override correctly takes priority\n")

    return True


def validate_state_transitions():
    """Validate that state machine prevents invalid transitions."""
    print("=" * 70)
    print("TEST 2: State Transition Validation")
    print("=" * 70)

    sm = AdvisoryStateMachine()

    # Test 1: Non-final to final (allowed)
    is_valid, reason = sm.validate_transition('pending_upstream', 'fixed')
    print(f"Test: pending_upstream → fixed")
    print(f"Expected: Valid (non-final → final allowed)")
    print(f"Actual: {'Valid' if is_valid else f'Invalid: {reason}'}")
    assert is_valid, "Non-final to final should be allowed"
    print("✅ PASS\n")

    # Test 2: Final to non-final (should reject)
    is_valid, reason = sm.validate_transition('fixed', 'pending_upstream')
    print(f"Test: fixed → pending_upstream")
    print(f"Expected: Invalid (regression)")
    print(f"Actual: {'Valid' if is_valid else f'Invalid: {reason}'}")
    assert not is_valid, "Final to non-final should be rejected"
    assert 'regression' in reason.lower(), "Should mention regression"
    print("✅ PASS: Regression correctly prevented\n")

    # Test 3: Final to different final (allowed)
    is_valid, reason = sm.validate_transition('fixed', 'not_applicable')
    print(f"Test: fixed → not_applicable")
    print(f"Expected: Valid (final → final allowed)")
    print(f"Actual: {'Valid' if is_valid else f'Invalid: {reason}'}")
    assert is_valid, "Final to final should be allowed"
    print("✅ PASS\n")

    return True


def validate_explanation_generation():
    """Validate that explanations are generated correctly."""
    print("=" * 70)
    print("TEST 3: Explanation Generation")
    print("=" * 70)

    explainer = DecisionExplainer()

    # Test CSV override explanation
    evidence = {
        'csv_reason': 'Package not used in production',
        'csv_updated_at': '2024-01-15T10:30:00'
    }

    explanation = explainer.explain('CSV_OVERRIDE', evidence)

    print(f"Reason: CSV_OVERRIDE")
    print(f"Evidence: {evidence}")
    print(f"Explanation: {explanation}")

    assert 'Echo security team' in explanation, "Should mention team"
    assert 'Package not used in production' in explanation, "Should include reason"
    assert '2024-01-15' in explanation, "Should include formatted date"
    print("✅ PASS: Explanation correctly generated\n")

    return True


def validate_full_decision_flow():
    """Validate complete decision-making flow with realistic scenarios."""
    print("=" * 70)
    print("TEST 4: Full Decision Flow - Realistic Scenarios")
    print("=" * 70)

    engine = RuleEngine()
    sm = AdvisoryStateMachine()
    explainer = DecisionExplainer()

    scenarios = [
        {
            'name': 'Scenario 1: Fixed upstream',
            'data': {
                'advisory_id': 'urllib3:CVE-2024-0001',
                'cve_id': 'CVE-2024-0001',
                'package_name': 'urllib3',
                'fix_available': True,
                'fixed_version': '2.0.7',
                'contributing_sources': ['osv', 'nvd'],
                'source_count': 2,
                'has_signal': True
            },
            'expected_state': 'fixed',
            'expected_rule': 'R2',
            'expected_confidence': 'high'
        },
        {
            'name': 'Scenario 2: NVD rejected CVE',
            'data': {
                'advisory_id': 'requests:CVE-2024-0002',
                'cve_id': 'CVE-2024-0002',
                'package_name': 'requests',
                'is_rejected': True,
                'nvd_rejection_status': 'rejected',
                'contributing_sources': ['nvd'],
                'source_count': 1,
                'has_signal': True
            },
            'expected_state': 'not_applicable',
            'expected_rule': 'R1',
            'expected_confidence': 'high'
        },
        {
            'name': 'Scenario 3: New CVE under investigation',
            'data': {
                'advisory_id': 'django:CVE-2024-9999',
                'cve_id': 'CVE-2024-9999',
                'package_name': 'django',
                'has_signal': False,
                'contributing_sources': ['echo_data'],
                'source_count': 1,
                'fix_available': False
            },
            'expected_state': 'under_investigation',
            'expected_rule': 'R5',
            'expected_confidence': 'low'
        },
        {
            'name': 'Scenario 4: Pending upstream fix',
            'data': {
                'advisory_id': 'flask:CVE-2024-0003',
                'cve_id': 'CVE-2024-0003',
                'package_name': 'flask',
                'has_signal': True,
                'fix_available': False,
                'cvss_score': 7.5,
                'contributing_sources': ['nvd', 'echo_data'],
                'source_count': 2
            },
            'expected_state': 'pending_upstream',
            'expected_rule': 'R6',
            'expected_confidence': 'medium'
        }
    ]

    for scenario in scenarios:
        print(f"\n{scenario['name']}")
        print("-" * 70)

        # Make decision
        decision = engine.decide(scenario['data'])

        print(f"Package: {scenario['data']['package_name']}")
        print(f"CVE: {scenario['data']['cve_id']}")
        print(f"Decision: {decision.state} (confidence: {decision.confidence})")
        print(f"Rule Applied: {decision.evidence['applied_rule']}")
        print(f"Explanation: {decision.explanation[:100]}...")

        # Validate decision
        assert decision.state == scenario['expected_state'], \
            f"Expected state {scenario['expected_state']}, got {decision.state}"
        assert decision.evidence['applied_rule'] == scenario['expected_rule'], \
            f"Expected rule {scenario['expected_rule']}, got {decision.evidence['applied_rule']}"
        assert decision.confidence == scenario['expected_confidence'], \
            f"Expected confidence {scenario['expected_confidence']}, got {decision.confidence}"

        # Validate state transition (simulate updating from unknown)
        is_valid, _ = sm.validate_transition(None, decision.state)
        assert is_valid, "New advisory should accept any valid state"

        print("✅ PASS")

    print()
    return True


def validate_batch_processing():
    """Validate batch processing performance."""
    print("=" * 70)
    print("TEST 5: Batch Processing")
    print("=" * 70)

    engine = RuleEngine()

    # Create batch of advisories
    advisories = [
        {
            'advisory_id': f'pkg{i}:CVE-2024-{i:04d}',
            'fix_available': i % 2 == 0,
            'fixed_version': f'{i}.0.0' if i % 2 == 0 else None,
            'has_signal': True
        }
        for i in range(10)
    ]

    print(f"Processing {len(advisories)} advisories in batch...")
    decisions = engine.decide_batch(advisories)

    print(f"Decisions made: {len(decisions)}")
    print(f"States: {set(d.state for d in decisions)}")

    assert len(decisions) == len(advisories), "Should process all advisories"

    # Validate distribution
    fixed_count = sum(1 for d in decisions if d.state == 'fixed')
    pending_count = sum(1 for d in decisions if d.state == 'pending_upstream')

    print(f"Fixed: {fixed_count}")
    print(f"Pending: {pending_count}")

    assert fixed_count == 5, "Should have 5 fixed (even indices)"
    assert pending_count == 5, "Should have 5 pending (odd indices)"

    print("✅ PASS: Batch processing works correctly\n")

    return True


def validate_determinism():
    """Validate that decisions are deterministic."""
    print("=" * 70)
    print("TEST 6: Determinism")
    print("=" * 70)

    engine = RuleEngine()

    test_data = {
        'advisory_id': 'test:CVE-2024-0001',
        'fix_available': True,
        'fixed_version': '1.2.3',
        'contributing_sources': ['osv']
    }

    print("Running same decision 100 times...")

    decisions = [engine.decide(test_data) for _ in range(100)]

    # All should be identical
    states = set(d.state for d in decisions)
    reasons = set(d.reason_code for d in decisions)

    print(f"Unique states: {states}")
    print(f"Unique reason codes: {reasons}")

    assert len(states) == 1, "All decisions should have same state"
    assert len(reasons) == 1, "All decisions should have same reason"

    print("✅ PASS: Decisions are deterministic\n")

    return True


def validate_error_handling():
    """Validate error handling for edge cases."""
    print("=" * 70)
    print("TEST 7: Error Handling")
    print("=" * 70)

    engine = RuleEngine()

    # Test with missing fields
    minimal_data = {
        'advisory_id': 'minimal:CVE-2024-0001'
    }

    print("Testing with minimal data (missing most fields)...")
    decision = engine.decide(minimal_data)

    print(f"State: {decision.state}")
    print(f"Rule: {decision.evidence['applied_rule']}")

    # Should fall back to default rule
    assert decision is not None, "Should handle missing data gracefully"
    assert decision.state in ['under_investigation', 'pending_upstream'], \
        "Should use fallback rule for minimal data"

    print("✅ PASS: Error handling works correctly\n")

    return True


def main():
    """Run all validation tests."""
    print("\n" + "=" * 70)
    print("PHASE 5 DECISIONING LAYER - VALIDATION SUITE")
    print("=" * 70 + "\n")

    tests = [
        ("Rule Priority", validate_rule_priority),
        ("State Transitions", validate_state_transitions),
        ("Explanation Generation", validate_explanation_generation),
        ("Full Decision Flow", validate_full_decision_flow),
        ("Batch Processing", validate_batch_processing),
        ("Determinism", validate_determinism),
        ("Error Handling", validate_error_handling),
    ]

    results = []

    for test_name, test_func in tests:
        try:
            success = test_func()
            results.append((test_name, "PASS", None))
        except AssertionError as e:
            results.append((test_name, "FAIL", str(e)))
            print(f"❌ FAIL: {e}\n")
        except Exception as e:
            results.append((test_name, "ERROR", str(e)))
            print(f"❌ ERROR: {e}\n")

    # Summary
    print("=" * 70)
    print("VALIDATION SUMMARY")
    print("=" * 70)

    for test_name, status, error in results:
        symbol = "✅" if status == "PASS" else "❌"
        print(f"{symbol} {test_name}: {status}")
        if error:
            print(f"   Error: {error}")

    passed = sum(1 for _, status, _ in results if status == "PASS")
    total = len(results)

    print(f"\nTotal: {passed}/{total} tests passed")

    if passed == total:
        print("\n🎉 ALL VALIDATION TESTS PASSED!")
        print("Phase 5 decisioning layer is working correctly.")
        return 0
    else:
        print("\n⚠️  SOME TESTS FAILED")
        print("Please review the failures above.")
        return 1


if __name__ == '__main__':
    sys.exit(main())
