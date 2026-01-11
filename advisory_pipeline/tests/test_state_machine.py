"""
Tests for advisory state machine.

Validates state transition rules and prevents invalid regressions.
"""
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from decisioning import AdvisoryStateMachine, StateType


class TestAdvisoryStateMachine:
    """Test state transition validation."""

    def test_new_advisory_allows_any_state(self):
        """New advisories (no current state) can enter any valid state."""
        sm = AdvisoryStateMachine()

        for state in ['fixed', 'not_applicable', 'pending_upstream', 'under_investigation']:
            is_valid, reason = sm.validate_transition(None, state)
            assert is_valid
            assert reason is None

    def test_non_final_to_any_allowed(self):
        """Non-final states can transition to any state."""
        sm = AdvisoryStateMachine()

        non_final_states = ['pending_upstream', 'under_investigation', 'unknown']
        target_states = ['fixed', 'not_applicable', 'wont_fix', 'pending_upstream']

        for current in non_final_states:
            for target in target_states:
                is_valid, reason = sm.validate_transition(current, target)
                assert is_valid, f"{current} -> {target} should be valid"

    def test_final_to_non_final_rejected(self):
        """Final states cannot transition to non-final (regression)."""
        sm = AdvisoryStateMachine()

        final_states = ['fixed', 'not_applicable', 'wont_fix']
        non_final_states = ['pending_upstream', 'under_investigation', 'unknown']

        for current in final_states:
            for target in non_final_states:
                is_valid, reason = sm.validate_transition(current, target)
                assert not is_valid, f"{current} -> {target} should be rejected"
                assert 'regression' in reason.lower()

    def test_final_to_final_allowed(self):
        """Final states can transition to other final states."""
        sm = AdvisoryStateMachine()

        final_states = ['fixed', 'not_applicable', 'wont_fix']

        for current in final_states:
            for target in final_states:
                is_valid, reason = sm.validate_transition(current, target)
                assert is_valid, f"{current} -> {target} should be valid"

    def test_same_state_transition_allowed(self):
        """Transitioning to same state is always allowed (re-confirmation)."""
        sm = AdvisoryStateMachine()

        all_states = ['fixed', 'not_applicable', 'pending_upstream', 'under_investigation']

        for state in all_states:
            is_valid, reason = sm.validate_transition(state, state)
            assert is_valid
            assert reason is None

    def test_allow_regressions_flag(self):
        """Regressions can be allowed if flag is set."""
        sm = AdvisoryStateMachine()

        # Normally rejected
        is_valid, reason = sm.validate_transition('fixed', 'pending_upstream', allow_regressions=False)
        assert not is_valid

        # But allowed with flag
        is_valid, reason = sm.validate_transition('fixed', 'pending_upstream', allow_regressions=True)
        assert is_valid

    def test_invalid_states_rejected(self):
        """Invalid state names should be rejected."""
        sm = AdvisoryStateMachine()

        is_valid, reason = sm.validate_transition(None, 'invalid_state')
        assert not is_valid
        assert 'invalid' in reason.lower()

        is_valid, reason = sm.validate_transition('invalid_current', 'fixed')
        assert not is_valid
        assert 'invalid' in reason.lower()

    def test_get_state_type(self):
        """Should correctly classify states."""
        sm = AdvisoryStateMachine()

        assert sm.get_state_type('fixed') == StateType.FINAL
        assert sm.get_state_type('not_applicable') == StateType.FINAL
        assert sm.get_state_type('wont_fix') == StateType.FINAL

        assert sm.get_state_type('pending_upstream') == StateType.NON_FINAL
        assert sm.get_state_type('under_investigation') == StateType.NON_FINAL
        assert sm.get_state_type('unknown') == StateType.NON_FINAL

        assert sm.get_state_type('invalid') is None

    def test_is_final_state(self):
        """Should correctly identify final states."""
        sm = AdvisoryStateMachine()

        assert sm.is_final_state('fixed')
        assert sm.is_final_state('not_applicable')
        assert sm.is_final_state('wont_fix')

        assert not sm.is_final_state('pending_upstream')
        assert not sm.is_final_state('under_investigation')
        assert not sm.is_final_state('unknown')

    def test_get_allowed_transitions(self):
        """Should return correct allowed transitions."""
        sm = AdvisoryStateMachine()

        # Non-final can go anywhere
        allowed = sm.get_allowed_transitions('pending_upstream')
        assert 'fixed' in allowed
        assert 'not_applicable' in allowed
        assert 'under_investigation' in allowed

        # Final can only go to final
        allowed = sm.get_allowed_transitions('fixed')
        assert 'not_applicable' in allowed
        assert 'wont_fix' in allowed
        assert 'pending_upstream' not in allowed
        assert 'under_investigation' not in allowed

    def test_describe_transition(self):
        """Should provide detailed transition description."""
        sm = AdvisoryStateMachine()

        description = sm.describe_transition('pending_upstream', 'fixed')

        assert description['from_state'] == 'pending_upstream'
        assert description['to_state'] == 'fixed'
        assert description['is_valid'] is True
        assert description['from_type'] == 'non_final'
        assert description['to_type'] == 'final'
        assert description['is_regression'] is False

    def test_describe_regression(self):
        """Should identify regressions in description."""
        sm = AdvisoryStateMachine()

        description = sm.describe_transition('fixed', 'pending_upstream')

        assert description['is_valid'] is False
        assert description['is_regression'] is True
        assert 'regression' in description['rejection_reason'].lower()

    def test_custom_state_configuration(self):
        """Should support custom state definitions."""
        config = {
            'final': ['resolved', 'dismissed'],
            'non_final': ['open', 'investigating']
        }

        sm = AdvisoryStateMachine(config)

        assert sm.is_final_state('resolved')
        assert sm.is_final_state('dismissed')
        assert not sm.is_final_state('fixed')  # Not in custom config

        assert not sm.is_final_state('open')
        assert not sm.is_final_state('investigating')
