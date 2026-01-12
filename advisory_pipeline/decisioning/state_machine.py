"""
State machine for validating advisory state transitions.

Ensures that state changes follow allowed transition paths and
prevents invalid regressions (e.g., fixed -> pending_upstream).
"""
from typing import Set, Dict, Optional, List, Any
from enum import Enum
import logging


logger = logging.getLogger(__name__)


class StateType(Enum):
    """State classification."""
    FINAL = "final"
    NON_FINAL = "non_final"


class AdvisoryStateMachine:
    """
    Validates state transitions for advisory lifecycle.

    State model:
    - Final states: fixed, not_applicable, wont_fix (terminal)
    - Non-final states: pending_upstream, under_investigation, unknown (can change)

    Transition rules:
    - Non-final -> Any: Allowed (new information)
    - Final -> Same final: Allowed (re-confirmation)
    - Final -> Different final: Allowed with warning (rare, but valid)
    - Final -> Non-final: Rejected (regression)
    """

    FINAL_STATES: Set[str] = {'fixed', 'not_applicable', 'wont_fix'}
    NON_FINAL_STATES: Set[str] = {'pending_upstream', 'under_investigation', 'unknown'}

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize state machine.

        Args:
            config: Optional configuration with custom state definitions
        """
        if config:
            self.final_states = set(config.get('final', self.FINAL_STATES))
            self.non_final_states = set(config.get('non_final', self.NON_FINAL_STATES))
        else:
            self.final_states = self.FINAL_STATES
            self.non_final_states = self.NON_FINAL_STATES

        self.all_states = self.final_states | self.non_final_states

    def validate_transition(
        self,
        current_state: Optional[str],
        new_state: str,
        allow_regressions: bool = False
    ) -> tuple[bool, Optional[str]]:
        """
        Validate if a state transition is allowed.

        Args:
            current_state: Current state (None if new advisory)
            new_state: Proposed new state
            allow_regressions: If True, allow final -> non-final transitions

        Returns:
            Tuple of (is_valid, reason)
            - is_valid: True if transition is allowed
            - reason: Explanation if transition is rejected, None otherwise
        """
        # Validate states exist
        if new_state not in self.all_states:
            return False, f"Invalid target state: {new_state}"

        # New advisory - always allowed
        if current_state is None:
            return True, None

        if current_state not in self.all_states:
            return False, f"Invalid current state: {current_state}"

        # Same state - always allowed
        if current_state == new_state:
            return True, None

        current_is_final = current_state in self.final_states
        new_is_final = new_state in self.final_states

        # Non-final -> Any: Allowed
        if not current_is_final:
            return True, None

        # Final -> Non-final: Regression (usually not allowed)
        if current_is_final and not new_is_final:
            if allow_regressions:
                logger.warning(
                    f"Allowing regression: {current_state} -> {new_state}"
                )
                return True, None
            else:
                return False, f"Regression not allowed: {current_state} (final) -> {new_state} (non-final)"

        # Final -> Final: Allowed but log
        if current_is_final and new_is_final:
            if current_state != new_state:
                logger.info(
                    f"Final state change: {current_state} -> {new_state}"
                )
            return True, None

        return True, None

    def get_state_type(self, state: str) -> Optional[StateType]:
        """Get the type classification for a state."""
        if state in self.final_states:
            return StateType.FINAL
        elif state in self.non_final_states:
            return StateType.NON_FINAL
        return None

    def is_final_state(self, state: str) -> bool:
        """Check if state is final/terminal."""
        return state in self.final_states

    def get_allowed_transitions(self, current_state: str) -> List[str]:
        """
        Get list of allowed target states from current state.

        Args:
            current_state: Starting state

        Returns:
            List of allowed target states
        """
        if current_state not in self.all_states:
            return []

        if current_state in self.non_final_states:
            # Non-final can transition to any state
            return list(self.all_states)

        if current_state in self.final_states:
            # Final can only transition to other final states
            return list(self.final_states)

        return []

    def describe_transition(
        self,
        current_state: Optional[str],
        new_state: str
    ) -> Dict[str, Any]:
        """
        Describe a state transition with metadata.

        Returns:
            Dictionary with transition details and validity
        """
        is_valid, reason = self.validate_transition(current_state, new_state)

        return {
            'from_state': current_state,
            'to_state': new_state,
            'is_valid': is_valid,
            'rejection_reason': reason,
            'from_type': self.get_state_type(current_state).value if current_state else None,
            'to_type': self.get_state_type(new_state).value if new_state else None,
            'is_regression': (
                current_state in self.final_states and
                new_state in self.non_final_states
            ) if current_state else False
        }
