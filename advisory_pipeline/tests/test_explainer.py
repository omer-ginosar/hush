"""
Tests for decision explainer.

Validates explanation generation from templates and evidence.
"""
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from decisioning import DecisionExplainer


class TestDecisionExplainer:
    """Test explanation generation."""

    def test_csv_override_explanation(self):
        """Should generate correct CSV override explanation."""
        explainer = DecisionExplainer()

        evidence = {
            'csv_reason': 'False positive - code not used in production',
            'csv_updated_at': '2024-01-15T10:30:00'
        }

        explanation = explainer.explain('CSV_OVERRIDE', evidence)

        assert 'Echo security team' in explanation
        assert 'False positive - code not used in production' in explanation
        assert '2024-01-15' in explanation

    def test_nvd_rejected_explanation(self):
        """Should generate correct NVD rejected explanation."""
        explainer = DecisionExplainer()

        evidence = {'is_rejected': True}

        explanation = explainer.explain('NVD_REJECTED', evidence)

        assert 'rejected' in explanation.lower()
        assert 'National Vulnerability Database' in explanation

    def test_upstream_fix_explanation(self):
        """Should generate correct upstream fix explanation."""
        explainer = DecisionExplainer()

        evidence = {
            'fix_available': True,
            'fixed_version': '2.1.0'
        }

        explanation = explainer.explain('UPSTREAM_FIX', evidence, fixed_version='2.1.0')

        assert '2.1.0' in explanation
        assert 'Fixed in version' in explanation
        assert 'upstream' in explanation.lower()

    def test_new_cve_explanation(self):
        """Should generate correct new CVE explanation."""
        explainer = DecisionExplainer()

        evidence = {'has_signal': False}

        explanation = explainer.explain('NEW_CVE', evidence)

        assert 'under analysis' in explanation.lower()
        assert 'awaiting' in explanation.lower()

    def test_awaiting_fix_explanation(self):
        """Should generate correct awaiting fix explanation."""
        explainer = DecisionExplainer()

        evidence = {
            'contributing_sources': ['nvd', 'osv', 'echo_data']
        }

        explanation = explainer.explain('AWAITING_FIX', evidence)

        assert 'No fix currently available' in explanation
        assert 'nvd, osv, echo_data' in explanation

    def test_handles_missing_template_variables(self):
        """Should handle missing template variables gracefully."""
        explainer = DecisionExplainer()

        evidence = {}  # Missing expected fields

        # Should not raise, should use defaults
        explanation = explainer.explain('CSV_OVERRIDE', evidence)

        assert 'unknown' in explanation.lower() or 'internal policy' in explanation.lower()

    def test_handles_none_values(self):
        """Should handle None values in evidence."""
        explainer = DecisionExplainer()

        evidence = {
            'csv_reason': None,
            'csv_updated_at': None
        }

        explanation = explainer.explain('CSV_OVERRIDE', evidence)

        assert explanation  # Should generate something
        assert 'none' not in explanation.lower()  # Should substitute defaults

    def test_formats_dates_correctly(self):
        """Should format datetime strings to readable dates."""
        explainer = DecisionExplainer()

        evidence = {
            'csv_reason': 'Test',
            'csv_updated_at': '2024-01-15T14:30:00Z'
        }

        explanation = explainer.explain('CSV_OVERRIDE', evidence)

        assert '2024-01-15' in explanation
        assert 'T14:30:00' not in explanation  # Should strip time

    def test_handles_empty_sources_list(self):
        """Should handle empty sources list gracefully."""
        explainer = DecisionExplainer()

        evidence = {
            'contributing_sources': []
        }

        explanation = explainer.explain('AWAITING_FIX', evidence)

        assert 'none' in explanation.lower()

    def test_fallback_for_unknown_reason_code(self):
        """Should provide fallback explanation for unknown reason codes."""
        explainer = DecisionExplainer()

        evidence = {'state': 'pending_upstream'}

        explanation = explainer.explain('UNKNOWN_REASON', evidence)

        assert explanation  # Should generate something
        assert 'pending_upstream' in explanation or 'pipeline' in explanation

    def test_custom_templates(self):
        """Should support custom explanation templates."""
        custom_templates = {
            'CUSTOM_RULE': 'Custom explanation with {field1} and {field2}.'
        }

        explainer = DecisionExplainer(templates=custom_templates)

        evidence = {
            'field1': 'value1',
            'field2': 'value2'
        }

        explanation = explainer.explain('CUSTOM_RULE', evidence)

        assert 'value1' in explanation
        assert 'value2' in explanation

    def test_explain_with_context_includes_metadata(self):
        """Should include metadata when requested."""
        explainer = DecisionExplainer()

        evidence = {
            'confidence': 'high',
            'applied_rule': 'R2',
            'source_count': 3,
            'contributing_sources': ['osv', 'nvd']
        }

        result = explainer.explain_with_context(
            'UPSTREAM_FIX',
            evidence,
            fixed_version='1.2.3',
            include_metadata=True
        )

        assert 'explanation' in result
        assert 'metadata' in result
        assert result['metadata']['confidence'] == 'high'
        assert result['metadata']['applied_rule'] == 'R2'
        assert result['metadata']['source_count'] == 3

    def test_explain_with_context_excludes_metadata_by_default(self):
        """Should exclude metadata by default."""
        explainer = DecisionExplainer()

        evidence = {'fix_available': True}

        result = explainer.explain_with_context(
            'UPSTREAM_FIX',
            evidence,
            fixed_version='1.0.0'
        )

        assert 'explanation' in result
        assert 'metadata' not in result
