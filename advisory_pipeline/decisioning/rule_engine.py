"""
Rule engine that evaluates advisory data against a rule chain.

The engine applies rules in priority order (lowest first) and returns
the first matching decision. This implements a deterministic,
explainable decision-making process.
"""
from typing import List, Dict, Any, Optional
import logging

from .rules import Rule, Decision, get_default_rules


logger = logging.getLogger(__name__)


class RuleEngine:
    """
    Deterministic rule engine for advisory state decisions.

    Rules are evaluated in priority order (0 is highest priority).
    First rule that matches determines the final state.
    """

    def __init__(self, rules: Optional[List[Rule]] = None):
        """
        Initialize the rule engine.

        Args:
            rules: List of rules to evaluate. If None, uses default rules.
        """
        self.rules = sorted(rules or get_default_rules(), key=lambda r: r.priority)

    def decide(self, advisory_data: Dict[str, Any]) -> Decision:
        """
        Apply rule chain to advisory data.

        Args:
            advisory_data: Enriched advisory data with all signals

        Returns:
            Decision object with state, explanation, and evidence

        Raises:
            ValueError: If no rule matches (should never happen with proper fallback rule)
        """
        advisory_id = advisory_data.get('advisory_id', 'unknown')

        for rule in self.rules:
            try:
                decision = rule.evaluate(advisory_data)
                if decision:
                    logger.debug(
                        f"Advisory {advisory_id}: Rule {rule.rule_id} matched -> {decision.state}"
                    )
                    # Add rule ID to decision metadata
                    decision.evidence['applied_rule'] = rule.rule_id
                    return decision

            except Exception as e:
                logger.error(
                    f"Error evaluating rule {rule.rule_id} for advisory {advisory_id}: {e}",
                    exc_info=True
                )
                continue

        # Should never reach here if fallback rule is present
        raise ValueError(f"No rule matched for advisory {advisory_id}")

    def decide_batch(self, advisories: List[Dict[str, Any]]) -> List[Decision]:
        """
        Apply rule chain to multiple advisories.

        Args:
            advisories: List of enriched advisory data

        Returns:
            List of decisions in same order as input
        """
        decisions = []
        for advisory in advisories:
            try:
                decision = self.decide(advisory)
                decisions.append(decision)
            except Exception as e:
                logger.error(
                    f"Failed to decide for advisory {advisory.get('advisory_id')}: {e}",
                    exc_info=True
                )
                # Add error decision
                decisions.append(self._create_error_decision(advisory, str(e)))

        return decisions

    def _create_error_decision(self, advisory_data: Dict[str, Any], error: str) -> Decision:
        """Create a fallback decision when processing fails."""
        return Decision(
            state='unknown',
            state_type='non_final',
            fixed_version=None,
            confidence='low',
            reason_code='ERROR',
            evidence={
                'error': error,
                'advisory_id': advisory_data.get('advisory_id')
            },
            explanation=f"Error processing advisory: {error}",
            contributing_sources=[],
            dissenting_sources=[]
        )

    def explain_decision(self, advisory_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get detailed explanation of decision process.

        Args:
            advisory_data: Enriched advisory data

        Returns:
            Dictionary with decision, matching rule, and evaluation trace
        """
        trace = []
        matched_decision = None

        for rule in self.rules:
            try:
                decision = rule.evaluate(advisory_data)
                trace.append({
                    'rule_id': rule.rule_id,
                    'priority': rule.priority,
                    'matched': decision is not None,
                    'result': decision.state if decision else None
                })

                if decision and matched_decision is None:
                    matched_decision = decision
                    decision.evidence['applied_rule'] = rule.rule_id

            except Exception as e:
                trace.append({
                    'rule_id': rule.rule_id,
                    'priority': rule.priority,
                    'matched': False,
                    'error': str(e)
                })

        return {
            'advisory_id': advisory_data.get('advisory_id'),
            'decision': matched_decision,
            'evaluation_trace': trace,
            'total_rules_evaluated': len(trace)
        }
