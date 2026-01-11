"""
Rule definitions for advisory state determination.

Each rule evaluates enriched advisory data and returns a decision
if the rule conditions are met, or None if the rule doesn't apply.
"""
from dataclasses import dataclass
from typing import Optional, Dict, Any, List
from abc import ABC, abstractmethod


@dataclass
class Decision:
    """Result of applying a rule to an advisory."""
    state: str  # fixed | not_applicable | wont_fix | pending_upstream | under_investigation
    state_type: str  # final | non_final
    fixed_version: Optional[str]
    confidence: str  # high | medium | low
    reason_code: str
    evidence: Dict[str, Any]
    explanation: str
    contributing_sources: List[str]
    dissenting_sources: List[str]


class Rule(ABC):
    """Base class for all decision rules."""

    def __init__(self, rule_id: str, priority: int, reason_code: str):
        self.rule_id = rule_id
        self.priority = priority
        self.reason_code = reason_code

    @abstractmethod
    def evaluate(self, advisory_data: Dict[str, Any]) -> Optional[Decision]:
        """
        Evaluate the rule against advisory data.

        Returns Decision if rule applies, None otherwise.
        """
        pass

    def _extract_sources(self, advisory_data: Dict[str, Any]) -> List[str]:
        """Extract contributing sources from advisory data."""
        sources = advisory_data.get('contributing_sources', [])
        if isinstance(sources, str):
            import json
            try:
                sources = json.loads(sources)
            except (json.JSONDecodeError, TypeError):
                sources = []
        return sources if isinstance(sources, list) else []


class CsvOverrideRule(Rule):
    """R0: CSV override - highest priority internal decision."""

    def __init__(self):
        super().__init__("R0", 0, "CSV_OVERRIDE")

    def evaluate(self, advisory_data: Dict[str, Any]) -> Optional[Decision]:
        override_status = advisory_data.get('override_status')

        if override_status == 'not_applicable':
            return Decision(
                state='not_applicable',
                state_type='final',
                fixed_version=None,
                confidence='high',
                reason_code=self.reason_code,
                evidence={
                    'csv_override': override_status,
                    'csv_reason': advisory_data.get('override_reason'),
                    'csv_updated_at': str(advisory_data.get('csv_updated_at')) if advisory_data.get('csv_updated_at') else None
                },
                explanation=self._build_explanation(advisory_data),
                contributing_sources=['echo_csv'],
                dissenting_sources=[]
            )

        return None

    def _build_explanation(self, advisory_data: Dict[str, Any]) -> str:
        reason = advisory_data.get('override_reason', 'Internal policy')
        updated = advisory_data.get('csv_updated_at')
        updated_str = str(updated) if updated else 'unknown date'
        return f"Marked as not applicable by Echo security team. Reason: {reason}. Updated: {updated_str}."


class NvdRejectedRule(Rule):
    """R1: CVE rejected by NVD."""

    def __init__(self):
        super().__init__("R1", 1, "NVD_REJECTED")

    def evaluate(self, advisory_data: Dict[str, Any]) -> Optional[Decision]:
        is_rejected = advisory_data.get('is_rejected', False)

        if is_rejected:
            return Decision(
                state='not_applicable',
                state_type='final',
                fixed_version=None,
                confidence='high',
                reason_code=self.reason_code,
                evidence={
                    'is_rejected': True,
                    'nvd_rejection_status': advisory_data.get('nvd_rejection_status')
                },
                explanation="This CVE has been rejected by the National Vulnerability Database.",
                contributing_sources=['nvd'],
                dissenting_sources=[]
            )

        return None


class UpstreamFixRule(Rule):
    """R2: Fix available upstream."""

    def __init__(self):
        super().__init__("R2", 2, "UPSTREAM_FIX")

    def evaluate(self, advisory_data: Dict[str, Any]) -> Optional[Decision]:
        fix_available = advisory_data.get('fix_available', False)
        fixed_version = advisory_data.get('fixed_version')

        if fix_available and fixed_version:
            return Decision(
                state='fixed',
                state_type='final',
                fixed_version=fixed_version,
                confidence='high',
                reason_code=self.reason_code,
                evidence={
                    'fix_available': True,
                    'fixed_version': fixed_version,
                    'osv_fixed_version': advisory_data.get('osv_fixed_version')
                },
                explanation=f"Fixed in version {fixed_version}. Fix available from upstream.",
                contributing_sources=self._extract_sources(advisory_data),
                dissenting_sources=[]
            )

        return None


class UnderInvestigationRule(Rule):
    """R5: New CVE with no substantive signals yet."""

    def __init__(self):
        super().__init__("R5", 5, "NEW_CVE")

    def evaluate(self, advisory_data: Dict[str, Any]) -> Optional[Decision]:
        has_signal = advisory_data.get('has_signal', False)

        if not has_signal:
            return Decision(
                state='under_investigation',
                state_type='non_final',
                fixed_version=None,
                confidence='low',
                reason_code=self.reason_code,
                evidence={
                    'has_signal': False,
                    'source_count': advisory_data.get('source_count', 0)
                },
                explanation="Recently published CVE under analysis. Awaiting upstream signals.",
                contributing_sources=self._extract_sources(advisory_data),
                dissenting_sources=[]
            )

        return None


class PendingUpstreamRule(Rule):
    """R6: Default rule - pending upstream fix."""

    def __init__(self):
        super().__init__("R6", 6, "AWAITING_FIX")

    def evaluate(self, advisory_data: Dict[str, Any]) -> Optional[Decision]:
        # This is the default/fallback rule - always applies
        sources = self._extract_sources(advisory_data)

        return Decision(
            state='pending_upstream',
            state_type='non_final',
            fixed_version=None,
            confidence='medium',
            reason_code=self.reason_code,
            evidence={
                'fix_available': False,
                'cvss_score': advisory_data.get('cvss_score'),
                'source_count': advisory_data.get('source_count', 0)
            },
            explanation=f"No fix currently available upstream. Monitoring for updates. Sources consulted: {', '.join(sources) if sources else 'none'}.",
            contributing_sources=sources,
            dissenting_sources=[]
        )


def get_default_rules() -> List[Rule]:
    """
    Get the default rule chain in priority order.

    Rules are evaluated in order (lowest priority number first).
    First rule that matches determines the final state.

    To add a new rule:
    1. Create a class extending Rule (see EXTENDING.md)
    2. Add instance here with appropriate priority
    3. Add tests in tests/test_decisioning_rules.py

    Example:
        # Add after UpstreamFixRule():
        # DistroNotAffectedRule(),  # Priority 3
        # DistroWontFixRule(),       # Priority 4
    """
    return [
        CsvOverrideRule(),        # R0 (priority 0): Internal override - highest
        NvdRejectedRule(),        # R1 (priority 1): NVD rejected
        UpstreamFixRule(),        # R2 (priority 2): Fix available
        # ADD NEW RULES HERE (priority 3-4 for distro-specific rules)
        # Example: DistroNotAffectedRule(),
        UnderInvestigationRule(), # R5 (priority 5): No signals yet
        PendingUpstreamRule(),    # R6 (priority 6): Default fallback - always matches
    ]


# ==============================================================================
# RULE TEMPLATE - Copy and modify to add new rules
# ==============================================================================
#
# class MyNewRule(Rule):
#     """RX: Brief description of when this rule applies."""
#
#     def __init__(self):
#         super().__init__("RX", X, "MY_REASON_CODE")
#
#     def evaluate(self, advisory_data: Dict[str, Any]) -> Optional[Decision]:
#         """
#         Evaluate if this rule applies.
#
#         Returns Decision if matched, None otherwise.
#         """
#         # 1. Extract relevant fields
#         my_field = advisory_data.get('my_field')
#
#         # 2. Check if rule applies
#         if not my_field:
#             return None
#
#         # 3. Return decision
#         return Decision(
#             state='my_state',  # fixed | not_applicable | pending_upstream | etc.
#             state_type='final',  # final | non_final
#             fixed_version=advisory_data.get('fixed_version'),
#             confidence='high',  # high | medium | low
#             reason_code=self.reason_code,
#             evidence={
#                 'my_field': my_field,
#                 'context': advisory_data.get('other_field')
#             },
#             explanation=f"Explanation based on {my_field}",
#             contributing_sources=self._extract_sources(advisory_data),
#             dissenting_sources=[]
#         )
#
# Then add to get_default_rules() above with appropriate priority.
# See EXTENDING.md for full guide with examples.
# ==============================================================================


# ==============================================================================
# EXAMPLE: Distribution Not Affected Rule (R3)
# Uncomment and modify to add support for distribution-specific data
# ==============================================================================
#
# class DistroNotAffectedRule(Rule):
#     """R3: Distribution marks CVE as not affected in their package."""
#
#     def __init__(self):
#         super().__init__("R3", 3, "DISTRO_NOT_AFFECTED")
#
#     def evaluate(self, advisory_data: Dict[str, Any]) -> Optional[Decision]:
#         # Check if distro data indicates not affected
#         distro_status = advisory_data.get('distro_status')
#
#         if distro_status == 'not_affected':
#             distro = advisory_data.get('distro', 'unknown distribution')
#             notes = advisory_data.get('distro_notes', 'Not specified')
#
#             return Decision(
#                 state='not_applicable',
#                 state_type='final',
#                 fixed_version=None,
#                 confidence='high',
#                 reason_code=self.reason_code,
#                 evidence={
#                     'distro_status': distro_status,
#                     'distro_notes': notes,
#                     'distro': distro
#                 },
#                 explanation=f"Not affected in {distro}. Reason: {notes}.",
#                 contributing_sources=self._extract_sources(advisory_data),
#                 dissenting_sources=[]
#             )
#
#         return None
#
# To enable:
# 1. Uncomment this class
# 2. Add DistroNotAffectedRule() to get_default_rules() after UpstreamFixRule()
# 3. Add 'distro_status', 'distro_notes', 'distro' fields to dbt enrichment
# 4. Add explanation template to config.yaml:
#    DISTRO_NOT_AFFECTED: "Not affected in {distro}. Reason: {distro_notes}."
# 5. Create ingestion adapter for distro data (e.g., UbuntuAdapter, DebianAdapter)
# ==============================================================================
