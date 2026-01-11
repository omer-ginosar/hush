#!/usr/bin/env python3
"""
Example: Adding a Distribution-Specific Rule

This shows how to add R3 (Distro Not Affected) rule to the decisioning layer.
Copy this pattern to add any new rule.

To integrate:
1. Copy DistroNotAffectedRule class to decisioning/rules.py
2. Add to get_default_rules() with priority 3
3. Update dbt enrichment to include distro fields
4. Add explanation template to config.yaml
5. Write tests
"""
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from decisioning.rules import Rule, Decision


class DistroNotAffectedRule(Rule):
    """
    R3: Distribution marks CVE as not affected.

    This rule applies when a Linux distribution (Ubuntu, Debian, etc.)
    has analyzed a CVE and determined it doesn't affect their package
    build, often because:
    - Vulnerable code path not included in distro build
    - Mitigations already in place
    - Different version/configuration
    """

    def __init__(self):
        super().__init__(
            rule_id="R3",
            priority=3,  # After upstream fix, before distro won't fix
            reason_code="DISTRO_NOT_AFFECTED"
        )

    def evaluate(self, advisory_data: Dict[str, Any]) -> Optional[Decision]:
        """
        Check if distro has marked CVE as not affected.

        Expected fields in advisory_data:
        - distro_status: 'not_affected' | 'affected' | 'needs-triage'
        - distro_notes: Human-readable explanation
        - distro: Distribution name and version (e.g., 'Ubuntu 22.04')
        """
        distro_status = advisory_data.get('distro_status')

        # Only apply if explicitly marked as not affected
        if distro_status != 'not_affected':
            return None

        # Extract context
        distro = advisory_data.get('distro', 'unknown distribution')
        notes = advisory_data.get('distro_notes', 'Not specified')

        return Decision(
            state='not_applicable',
            state_type='final',
            fixed_version=None,
            confidence='high',
            reason_code=self.reason_code,
            evidence={
                'distro_status': distro_status,
                'distro_notes': notes,
                'distro': distro,
                'distro_url': advisory_data.get('distro_url')
            },
            explanation=self._build_explanation(distro, notes),
            contributing_sources=self._extract_sources(advisory_data),
            dissenting_sources=[]
        )

    def _build_explanation(self, distro: str, notes: str) -> str:
        """Build customer-facing explanation."""
        return f"Not affected in {distro}. Reason: {notes}."


class DistroWontFixRule(Rule):
    """
    R4: Distribution has decided not to fix this CVE.

    This is distinct from "not affected" - the distro acknowledges
    the CVE but won't fix it (end of life, low severity, etc.)
    """

    def __init__(self):
        super().__init__(
            rule_id="R4",
            priority=4,
            reason_code="DISTRO_WONT_FIX"
        )

    def evaluate(self, advisory_data: Dict[str, Any]) -> Optional[Decision]:
        distro_status = advisory_data.get('distro_status')

        if distro_status != 'wont_fix':
            return None

        distro = advisory_data.get('distro', 'unknown distribution')
        notes = advisory_data.get('distro_notes', 'Not specified')

        return Decision(
            state='wont_fix',
            state_type='final',
            fixed_version=None,
            confidence='high',
            reason_code=self.reason_code,
            evidence={
                'distro_status': distro_status,
                'distro_notes': notes,
                'distro': distro
            },
            explanation=f"{distro} has marked this as will not fix. Reason: {notes}.",
            contributing_sources=self._extract_sources(advisory_data),
            dissenting_sources=[]
        )


def demo():
    """Demonstrate the distro rules."""
    from decisioning import RuleEngine

    # Create engine with distro rules
    custom_rules = [
        # ... existing rules ...
        DistroNotAffectedRule(),
        DistroWontFixRule(),
        # ... remaining rules ...
    ]

    # Note: Would need to pass custom rules to RuleEngine
    # engine = RuleEngine(rules=custom_rules)

    # Test data with distro signals
    test_cases = [
        {
            'name': 'Ubuntu Not Affected',
            'data': {
                'advisory_id': 'curl:CVE-2024-0001',
                'cve_id': 'CVE-2024-0001',
                'distro_status': 'not_affected',
                'distro_notes': 'Vulnerable code path not compiled in Ubuntu build',
                'distro': 'Ubuntu 22.04',
                'contributing_sources': ['ubuntu']
            },
            'expected_state': 'not_applicable',
            'expected_rule': 'R3'
        },
        {
            'name': 'Debian Won\'t Fix',
            'data': {
                'advisory_id': 'oldpkg:CVE-2024-0002',
                'cve_id': 'CVE-2024-0002',
                'distro_status': 'wont_fix',
                'distro_notes': 'Package is end-of-life in this release',
                'distro': 'Debian 10',
                'contributing_sources': ['debian']
            },
            'expected_state': 'wont_fix',
            'expected_rule': 'R4'
        }
    ]

    # Test rules directly
    r3 = DistroNotAffectedRule()
    r4 = DistroWontFixRule()

    for case in test_cases:
        print(f"\n{case['name']}")
        print("-" * 60)

        decision = r3.evaluate(case['data'])
        if not decision:
            decision = r4.evaluate(case['data'])

        if decision:
            print(f"State: {decision.state}")
            print(f"Rule: {decision.evidence.get('applied_rule', 'N/A')}")
            print(f"Confidence: {decision.confidence}")
            print(f"Explanation: {decision.explanation}")
        else:
            print("No rule matched")


if __name__ == '__main__':
    demo()
