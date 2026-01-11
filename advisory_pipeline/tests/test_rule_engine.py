"""
Tests for the rule engine.

Validates that the engine correctly applies the rule chain and
produces deterministic decisions.
"""
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from decisioning import RuleEngine, get_default_rules


class TestRuleEngine:
    """Test rule engine execution."""

    def test_applies_first_matching_rule(self):
        """Engine should return first matching rule's decision."""
        engine = RuleEngine()

        # CSV override should match first (priority 0)
        advisory_data = {
            'advisory_id': 'pkg:CVE-2024-0001',
            'override_status': 'not_applicable',
            'override_reason': 'False positive',
            'is_rejected': True,  # This would also match R1, but R0 has priority
        }

        decision = engine.decide(advisory_data)

        assert decision.reason_code == 'CSV_OVERRIDE'
        assert decision.state == 'not_applicable'
        assert decision.evidence['applied_rule'] == 'R0'

    def test_fallback_to_pending_upstream(self):
        """Should fall back to R6 when no higher priority rules match."""
        engine = RuleEngine()

        advisory_data = {
            'advisory_id': 'pkg:CVE-2024-0003',
            'override_status': None,
            'is_rejected': False,
            'fix_available': False,
            'has_signal': True,  # Has some signal, so not under investigation
            'contributing_sources': ['nvd'],
            'source_count': 1,
            'cvss_score': 7.5
        }

        decision = engine.decide(advisory_data)

        assert decision.reason_code == 'AWAITING_FIX'
        assert decision.state == 'pending_upstream'
        assert decision.state_type == 'non_final'

    def test_upstream_fix_rule(self):
        """R2 should match when fix is available."""
        engine = RuleEngine()

        advisory_data = {
            'advisory_id': 'pkg:CVE-2024-0001',
            'override_status': None,
            'is_rejected': False,
            'fix_available': True,
            'fixed_version': '2.0.0',
            'contributing_sources': ['osv']
        }

        decision = engine.decide(advisory_data)

        assert decision.reason_code == 'UPSTREAM_FIX'
        assert decision.state == 'fixed'
        assert decision.fixed_version == '2.0.0'

    def test_under_investigation_for_new_cve(self):
        """R5 should match for new CVEs with no signals."""
        engine = RuleEngine()

        advisory_data = {
            'advisory_id': 'pkg:CVE-2024-9999',
            'override_status': None,
            'is_rejected': False,
            'fix_available': False,
            'has_signal': False,
            'source_count': 1,
            'contributing_sources': ['echo_data']
        }

        decision = engine.decide(advisory_data)

        assert decision.reason_code == 'NEW_CVE'
        assert decision.state == 'under_investigation'
        assert decision.confidence == 'low'

    def test_decide_batch_processes_multiple_advisories(self):
        """Batch processing should handle multiple advisories."""
        engine = RuleEngine()

        advisories = [
            {
                'advisory_id': 'pkg1:CVE-2024-0001',
                'override_status': 'not_applicable',
                'override_reason': 'Test'
            },
            {
                'advisory_id': 'pkg2:CVE-2024-0002',
                'is_rejected': True
            },
            {
                'advisory_id': 'pkg3:CVE-2024-0003',
                'fix_available': True,
                'fixed_version': '1.0.0'
            }
        ]

        decisions = engine.decide_batch(advisories)

        assert len(decisions) == 3
        assert decisions[0].reason_code == 'CSV_OVERRIDE'
        assert decisions[1].reason_code == 'NVD_REJECTED'
        assert decisions[2].reason_code == 'UPSTREAM_FIX'

    def test_explain_decision_provides_trace(self):
        """Explain decision should provide full evaluation trace."""
        engine = RuleEngine()

        advisory_data = {
            'advisory_id': 'pkg:CVE-2024-0001',
            'fix_available': True,
            'fixed_version': '1.2.3'
        }

        explanation = engine.explain_decision(advisory_data)

        assert 'advisory_id' in explanation
        assert 'decision' in explanation
        assert 'evaluation_trace' in explanation
        assert explanation['total_rules_evaluated'] == 5

        # Check trace shows which rules were evaluated
        trace = explanation['evaluation_trace']
        rule_ids = [t['rule_id'] for t in trace]
        assert 'R0' in rule_ids
        assert 'R1' in rule_ids
        assert 'R2' in rule_ids

        # R2 should have matched
        r2_trace = next(t for t in trace if t['rule_id'] == 'R2')
        assert r2_trace['matched'] is True

    def test_deterministic_decisions(self):
        """Same input should always produce same decision."""
        engine = RuleEngine()

        advisory_data = {
            'advisory_id': 'pkg:CVE-2024-0001',
            'fix_available': True,
            'fixed_version': '1.0.0',
            'contributing_sources': ['osv']
        }

        decision1 = engine.decide(advisory_data)
        decision2 = engine.decide(advisory_data)

        assert decision1.state == decision2.state
        assert decision1.reason_code == decision2.reason_code
        assert decision1.confidence == decision2.confidence
