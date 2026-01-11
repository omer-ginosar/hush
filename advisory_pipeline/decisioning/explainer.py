"""
Explanation generator for advisory decisions.

Produces human-readable explanations from decision data using
templates and evidence.
"""
from typing import Dict, Any, Optional
from datetime import datetime
import logging


logger = logging.getLogger(__name__)


class DecisionExplainer:
    """
    Generates customer-facing explanations for advisory decisions.

    Uses templates with evidence-based substitution to create
    consistent, informative explanations.
    """

    DEFAULT_TEMPLATES = {
        'CSV_OVERRIDE': (
            "Marked as not applicable by Echo security team. "
            "Reason: {csv_reason}. Updated: {csv_updated_at}."
        ),
        'NVD_REJECTED': (
            "This CVE has been rejected by the National Vulnerability Database."
        ),
        'UPSTREAM_FIX': (
            "Fixed in version {fixed_version}. Fix available from upstream."
        ),
        'DISTRO_NOT_AFFECTED': (
            "Not affected in {distro}. Reason: {distro_notes}."
        ),
        'DISTRO_WONT_FIX': (
            "{distro} has marked this as will not fix. Reason: {distro_notes}."
        ),
        'NEW_CVE': (
            "Recently published CVE under analysis. Awaiting upstream signals."
        ),
        'AWAITING_FIX': (
            "No fix currently available upstream. "
            "Sources consulted: {sources_list}."
        ),
        'ERROR': (
            "Unable to determine status. Error: {error}"
        ),
        'DEFAULT': (
            "Status determined by enrichment pipeline."
        )
    }

    def __init__(self, templates: Optional[Dict[str, str]] = None):
        """
        Initialize explainer with templates.

        Args:
            templates: Custom explanation templates by reason code.
                      If None, uses default templates.
        """
        self.templates = templates or self.DEFAULT_TEMPLATES

    def explain(
        self,
        reason_code: str,
        evidence: Dict[str, Any],
        fixed_version: Optional[str] = None
    ) -> str:
        """
        Generate explanation from reason code and evidence.

        Args:
            reason_code: Decision reason code (e.g., 'UPSTREAM_FIX')
            evidence: Evidence dictionary with substitution values
            fixed_version: Fixed version if applicable

        Returns:
            Human-readable explanation string
        """
        template = self.templates.get(reason_code, self.templates.get('DEFAULT', ''))

        # Prepare substitution values
        values = self._prepare_values(evidence, fixed_version)

        try:
            explanation = template.format(**values)
            return explanation.strip()
        except KeyError as e:
            logger.warning(
                f"Missing template variable {e} for reason code {reason_code}"
            )
            # Fallback to basic explanation
            return self._create_fallback_explanation(reason_code, evidence)

    def _prepare_values(
        self,
        evidence: Dict[str, Any],
        fixed_version: Optional[str]
    ) -> Dict[str, str]:
        """
        Prepare evidence values for template substitution.

        Handles missing values, formatting, and type conversion.
        """
        values = {}

        # Extract all evidence values
        for key, value in evidence.items():
            if value is None:
                values[key] = 'unknown'
            elif isinstance(value, (list, dict)):
                values[key] = str(value)
            else:
                values[key] = str(value)

        # Add fixed version
        values['fixed_version'] = fixed_version or 'unknown'

        # Format specific fields
        if 'csv_reason' in values:
            values['csv_reason'] = values.get('csv_reason', 'Internal policy')

        if 'csv_updated_at' in values:
            updated = values.get('csv_updated_at', 'unknown')
            if updated and updated != 'unknown' and updated != 'None':
                try:
                    dt = datetime.fromisoformat(updated.replace('Z', '+00:00'))
                    values['csv_updated_at'] = dt.strftime('%Y-%m-%d')
                except (ValueError, AttributeError):
                    values['csv_updated_at'] = updated
            else:
                values['csv_updated_at'] = 'unknown date'

        # Format sources list
        if 'contributing_sources' in evidence:
            sources = evidence['contributing_sources']
            if isinstance(sources, list):
                values['sources_list'] = ', '.join(sources) if sources else 'none'
            else:
                values['sources_list'] = str(sources) if sources else 'none'

        # Ensure all template variables have defaults
        defaults = {
            'csv_reason': 'Internal policy',
            'csv_updated_at': 'unknown date',
            'nvd_rejection_reason': 'Not specified',
            'fixed_version': 'unknown',
            'fix_source': 'upstream',
            'fix_url': 'Not available',
            'distro': 'unknown',
            'distro_notes': 'Not specified',
            'first_seen': 'unknown',
            'last_checked': 'unknown',
            'sources_list': 'none',
            'error': 'Unknown error'
        }

        for key, default in defaults.items():
            if key not in values:
                values[key] = default

        return values

    def _create_fallback_explanation(
        self,
        reason_code: str,
        evidence: Dict[str, Any]
    ) -> str:
        """Create a basic explanation when template fails."""
        state = evidence.get('state', 'unknown')
        return f"Advisory classified as {state}. Reason: {reason_code}."

    def explain_with_context(
        self,
        reason_code: str,
        evidence: Dict[str, Any],
        fixed_version: Optional[str] = None,
        include_metadata: bool = False
    ) -> Dict[str, Any]:
        """
        Generate explanation with additional context.

        Args:
            reason_code: Decision reason code
            evidence: Evidence dictionary
            fixed_version: Fixed version if applicable
            include_metadata: If True, include decision metadata

        Returns:
            Dictionary with explanation and optional metadata
        """
        explanation = self.explain(reason_code, evidence, fixed_version)

        result = {'explanation': explanation}

        if include_metadata:
            result['metadata'] = {
                'reason_code': reason_code,
                'confidence': evidence.get('confidence', 'unknown'),
                'applied_rule': evidence.get('applied_rule', 'unknown'),
                'source_count': evidence.get('source_count', 0),
                'contributing_sources': evidence.get('contributing_sources', [])
            }

        return result
