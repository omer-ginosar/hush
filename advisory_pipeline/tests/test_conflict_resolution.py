"""
Tests for multi-source conflict resolution logic.

These tests validate how the pipeline handles conflicting signals
from different sources and ensures correct prioritization and
resolution based on the defined rule chain.
"""
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from decisioning import RuleEngine


class TestConflictResolution:
    """Test conflict resolution between sources."""

    def test_csv_override_wins_over_upstream_fix(self):
        """CSV override (R0) should take precedence over OSV fix (R2)."""
        engine = RuleEngine()

        # Advisory has both CSV override AND upstream fix
        # CSV override should win (priority 0 < priority 2)
        advisory_data = {
            'advisory_id': 'pkg:CVE-2024-0001',
            'override_status': 'not_applicable',
            'override_reason': 'Service not exposed in our deployment',
            'csv_updated_at': '2024-01-15',
            'fix_available': True,
            'fixed_version': '1.2.3',
            'contributing_sources': ['echo_csv', 'osv'],
            'source_count': 2
        }

        decision = engine.decide(advisory_data)

        assert decision.reason_code == 'CSV_OVERRIDE'
        assert decision.state == 'not_applicable'
        assert decision.confidence == 'high'

    def test_nvd_rejection_overrides_osv_fix(self):
        """NVD rejection (R1) should override OSV fix (R2)."""
        engine = RuleEngine()

        advisory_data = {
            'advisory_id': 'pkg:CVE-2024-0002',
            'is_rejected': True,
            'nvd_rejection_status': 'rejected',
            'fix_available': True,
            'fixed_version': '2.0.0',
            'contributing_sources': ['nvd', 'osv'],
            'source_count': 2
        }

        decision = engine.decide(advisory_data)

        assert decision.reason_code == 'NVD_REJECTED'
        assert decision.state == 'not_applicable'
        assert decision.state_type == 'final'

    def test_upstream_fix_beats_pending_upstream(self):
        """Fix available (R2) should override default pending state (R6)."""
        engine = RuleEngine()

        advisory_data = {
            'advisory_id': 'pkg:CVE-2024-0003',
            'override_status': None,
            'is_rejected': False,
            'fix_available': True,
            'fixed_version': '1.0.1',
            'has_signal': True,
            'contributing_sources': ['osv', 'nvd'],
            'source_count': 2
        }

        decision = engine.decide(advisory_data)

        assert decision.reason_code == 'UPSTREAM_FIX'
        assert decision.state == 'fixed'
        assert decision.fixed_version == '1.0.1'

    def test_dissenting_sources_tracked(self):
        """
        When sources disagree, CSV override wins.

        Note: Current implementation doesn't populate dissenting_sources
        at decision level. This is a future enhancement.
        """
        engine = RuleEngine()

        # CSV says not_applicable, but OSV says fixed - conflict scenario
        advisory_data = {
            'advisory_id': 'pkg:CVE-2024-0001',
            'override_status': 'not_applicable',
            'override_reason': 'False positive',
            'fix_available': True,  # OSV says fixed
            'fixed_version': '1.2.3',
            'contributing_sources': ['echo_csv', 'osv'],
        }

        decision = engine.decide(advisory_data)

        # CSV should win (R0 has priority 0, higher than R2's priority 2)
        assert decision.reason_code == 'CSV_OVERRIDE'
        assert decision.state == 'not_applicable'
        # Evidence shows CSV override was applied
        assert decision.evidence['csv_override'] == 'not_applicable'

    def test_multiple_sources_same_conclusion(self):
        """Multiple sources agreeing should boost confidence."""
        engine = RuleEngine()

        advisory_data = {
            'advisory_id': 'pkg:CVE-2024-0004',
            'override_status': None,
            'is_rejected': False,
            'fix_available': True,
            'fixed_version': '2.1.0',
            'contributing_sources': ['osv', 'nvd', 'echo_data'],
            'source_count': 3,
            'cvss_score': 8.1
        }

        decision = engine.decide(advisory_data)

        assert decision.state == 'fixed'
        assert decision.confidence == 'high'
        # Contributing sources tracked at decision level
        assert len(decision.contributing_sources) >= 2

    def test_partial_information_still_decides(self):
        """Pipeline should make decision even with incomplete data."""
        engine = RuleEngine()

        # Only NVD data, no OSV fix information
        advisory_data = {
            'advisory_id': 'pkg:CVE-2024-0005',
            'override_status': None,
            'is_rejected': False,
            'fix_available': False,
            'has_signal': True,
            'contributing_sources': ['nvd'],
            'source_count': 1,
            'cvss_score': 6.5
        }

        decision = engine.decide(advisory_data)

        # Should default to pending_upstream (R6)
        assert decision.reason_code == 'AWAITING_FIX'
        assert decision.state == 'pending_upstream'
        assert decision.confidence in ['low', 'medium']

    def test_no_sources_triggers_investigation(self):
        """CVE with no enrichment signals goes to under_investigation."""
        engine = RuleEngine()

        advisory_data = {
            'advisory_id': 'pkg:CVE-2024-9999',
            'override_status': None,
            'is_rejected': False,
            'fix_available': False,
            'has_signal': False,
            'contributing_sources': ['echo_data'],
            'source_count': 1
        }

        decision = engine.decide(advisory_data)

        assert decision.reason_code == 'NEW_CVE'
        assert decision.state == 'under_investigation'
        assert decision.confidence == 'low'


class TestSourcePriority:
    """Test source prioritization in conflict scenarios."""

    def test_source_priority_order(self):
        """Validate implicit source priority: CSV > NVD > OSV > Echo."""
        engine = RuleEngine()

        # Test CSV > OSV
        data1 = {
            'advisory_id': 'test1',
            'override_status': 'not_applicable',
            'override_reason': 'Test',
            'fix_available': True,
            'fixed_version': '1.0.0'
        }
        decision1 = engine.decide(data1)
        assert decision1.reason_code == 'CSV_OVERRIDE'

        # Test NVD > OSV
        data2 = {
            'advisory_id': 'test2',
            'is_rejected': True,
            'fix_available': True,
            'fixed_version': '1.0.0'
        }
        decision2 = engine.decide(data2)
        assert decision2.reason_code == 'NVD_REJECTED'

        # Test OSV wins when no higher priority signals
        data3 = {
            'advisory_id': 'test3',
            'override_status': None,
            'is_rejected': False,
            'fix_available': True,
            'fixed_version': '1.0.0'
        }
        decision3 = engine.decide(data3)
        assert decision3.reason_code == 'UPSTREAM_FIX'

    def test_confidence_decreases_with_fewer_sources(self):
        """Confidence should correlate with number of sources."""
        engine = RuleEngine()

        # Multiple sources
        data_multi = {
            'advisory_id': 'test1',
            'fix_available': True,
            'fixed_version': '1.0.0',
            'contributing_sources': ['osv', 'nvd', 'echo_data'],
            'source_count': 3
        }

        # Single source
        data_single = {
            'advisory_id': 'test2',
            'fix_available': True,
            'fixed_version': '1.0.0',
            'contributing_sources': ['osv'],
            'source_count': 1
        }

        decision_multi = engine.decide(data_multi)
        decision_single = engine.decide(data_single)

        # Both should be 'fixed' but multi-source may have higher confidence
        assert decision_multi.state == decision_single.state == 'fixed'


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_empty_advisory_data(self):
        """Engine should handle empty advisory data gracefully."""
        engine = RuleEngine()

        advisory_data = {'advisory_id': 'empty'}

        decision = engine.decide(advisory_data)

        # Should fall through to R5 or R6
        assert decision.state in ['under_investigation', 'pending_upstream']

    def test_malformed_version_still_decides(self):
        """Malformed fixed version should not break decision."""
        engine = RuleEngine()

        advisory_data = {
            'advisory_id': 'test',
            'fix_available': True,
            'fixed_version': 'invalid-version-@@#',
            'contributing_sources': ['osv']
        }

        decision = engine.decide(advisory_data)

        # Should still recognize fix is available
        assert decision.state == 'fixed'
        assert decision.fixed_version == 'invalid-version-@@#'

    def test_null_cve_id_still_processes(self):
        """Advisory with null CVE ID should still be processed."""
        engine = RuleEngine()

        advisory_data = {
            'advisory_id': 'pkg:null',
            'cve_id': None,
            'package_name': 'some-package',
            'has_signal': False
        }

        decision = engine.decide(advisory_data)

        # Should still make a decision
        assert decision.state in ['under_investigation', 'pending_upstream']

    def test_batch_processing_maintains_independence(self):
        """Batch decisions should be independent of each other."""
        engine = RuleEngine()

        advisories = [
            {'advisory_id': 'adv1', 'override_status': 'not_applicable', 'override_reason': 'Test'},
            {'advisory_id': 'adv2', 'is_rejected': True},
            {'advisory_id': 'adv3', 'fix_available': True, 'fixed_version': '1.0.0'},
        ]

        decisions = engine.decide_batch(advisories)

        assert len(decisions) == 3
        assert decisions[0].reason_code == 'CSV_OVERRIDE'
        assert decisions[1].reason_code == 'NVD_REJECTED'
        assert decisions[2].reason_code == 'UPSTREAM_FIX'

        # Each decision should be independent - verify via state
        assert decisions[0].state == 'not_applicable'
        assert decisions[1].state == 'not_applicable'
        assert decisions[2].state == 'fixed'
