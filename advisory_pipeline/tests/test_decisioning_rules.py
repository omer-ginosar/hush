"""
Tests for decision rules.

Validates that each rule correctly evaluates advisory data and
produces expected decisions.
"""
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from decisioning.rules import (
    CsvOverrideRule,
    NvdRejectedRule,
    UpstreamFixRule,
    UnderInvestigationRule,
    PendingUpstreamRule,
    get_default_rules
)


class TestCsvOverrideRule:
    """Test CSV override rule (R0)."""

    def test_matches_not_applicable_override(self):
        rule = CsvOverrideRule()
        advisory_data = {
            'advisory_id': 'pkg:CVE-2024-0001',
            'override_status': 'not_applicable',
            'override_reason': 'False positive',
            'csv_updated_at': '2024-01-15'
        }

        decision = rule.evaluate(advisory_data)

        assert decision is not None
        assert decision.state == 'not_applicable'
        assert decision.state_type == 'final'
        assert decision.confidence == 'high'
        assert decision.reason_code == 'CSV_OVERRIDE'
        assert 'csv_override' in decision.evidence

    def test_no_match_when_no_override(self):
        rule = CsvOverrideRule()
        advisory_data = {
            'advisory_id': 'pkg:CVE-2024-0001',
            'override_status': None
        }

        decision = rule.evaluate(advisory_data)
        assert decision is None


class TestNvdRejectedRule:
    """Test NVD rejected rule (R1)."""

    def test_matches_rejected_cve(self):
        rule = NvdRejectedRule()
        advisory_data = {
            'advisory_id': 'pkg:CVE-2024-0002',
            'is_rejected': True,
            'nvd_rejection_status': 'rejected'
        }

        decision = rule.evaluate(advisory_data)

        assert decision is not None
        assert decision.state == 'not_applicable'
        assert decision.state_type == 'final'
        assert decision.confidence == 'high'
        assert decision.reason_code == 'NVD_REJECTED'

    def test_no_match_when_not_rejected(self):
        rule = NvdRejectedRule()
        advisory_data = {
            'advisory_id': 'pkg:CVE-2024-0001',
            'is_rejected': False
        }

        decision = rule.evaluate(advisory_data)
        assert decision is None


class TestUpstreamFixRule:
    """Test upstream fix rule (R2)."""

    def test_matches_when_fix_available(self):
        rule = UpstreamFixRule()
        advisory_data = {
            'advisory_id': 'pkg:CVE-2024-0001',
            'fix_available': True,
            'fixed_version': '1.2.3',
            'osv_fixed_version': '1.2.3',
            'contributing_sources': ['osv', 'nvd']
        }

        decision = rule.evaluate(advisory_data)

        assert decision is not None
        assert decision.state == 'fixed'
        assert decision.state_type == 'final'
        assert decision.fixed_version == '1.2.3'
        assert decision.confidence == 'high'
        assert decision.reason_code == 'UPSTREAM_FIX'

    def test_no_match_when_no_version(self):
        rule = UpstreamFixRule()
        advisory_data = {
            'advisory_id': 'pkg:CVE-2024-0001',
            'fix_available': True,
            'fixed_version': None
        }

        decision = rule.evaluate(advisory_data)
        assert decision is None

    def test_no_match_when_fix_not_available(self):
        rule = UpstreamFixRule()
        advisory_data = {
            'advisory_id': 'pkg:CVE-2024-0001',
            'fix_available': False,
            'fixed_version': '1.2.3'
        }

        decision = rule.evaluate(advisory_data)
        assert decision is None


class TestUnderInvestigationRule:
    """Test under investigation rule (R5)."""

    def test_matches_when_no_signals(self):
        rule = UnderInvestigationRule()
        advisory_data = {
            'advisory_id': 'pkg:CVE-2024-0004',
            'has_signal': False,
            'source_count': 1,
            'contributing_sources': ['echo_data']
        }

        decision = rule.evaluate(advisory_data)

        assert decision is not None
        assert decision.state == 'under_investigation'
        assert decision.state_type == 'non_final'
        assert decision.confidence == 'low'
        assert decision.reason_code == 'NEW_CVE'

    def test_no_match_when_has_signals(self):
        rule = UnderInvestigationRule()
        advisory_data = {
            'advisory_id': 'pkg:CVE-2024-0001',
            'has_signal': True
        }

        decision = rule.evaluate(advisory_data)
        assert decision is None


class TestPendingUpstreamRule:
    """Test pending upstream rule (R6) - default fallback."""

    def test_always_matches(self):
        rule = PendingUpstreamRule()
        advisory_data = {
            'advisory_id': 'pkg:CVE-2024-0003',
            'contributing_sources': ['nvd', 'echo_data'],
            'source_count': 2,
            'cvss_score': 7.5
        }

        decision = rule.evaluate(advisory_data)

        assert decision is not None
        assert decision.state == 'pending_upstream'
        assert decision.state_type == 'non_final'
        assert decision.confidence == 'medium'
        assert decision.reason_code == 'AWAITING_FIX'


class TestDefaultRules:
    """Test default rule set."""

    def test_get_default_rules_returns_all_rules(self):
        rules = get_default_rules()

        assert len(rules) == 5
        rule_ids = [r.rule_id for r in rules]
        assert 'R0' in rule_ids
        assert 'R1' in rule_ids
        assert 'R2' in rule_ids
        assert 'R5' in rule_ids
        assert 'R6' in rule_ids

    def test_rules_have_correct_priorities(self):
        rules = get_default_rules()

        # Verify priority ordering
        priorities = [r.priority for r in rules]
        assert priorities == [0, 1, 2, 5, 6]
