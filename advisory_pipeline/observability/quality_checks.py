"""
Data quality checks for pipeline outputs.

This module implements QualityChecker, which runs SQL-based validation checks
against the advisory_state_history table after each pipeline run.

Checks implemented:
- No null states: Every advisory must have a state
- No orphan packages: Placeholder for package registry validation
- Explanation completeness: All advisories must have explanations
- Fixed has version: "fixed" state must include fixed_version
- CVE format: CVE IDs must match CVE-YYYY-NNNN pattern
- Stalled CVEs: Detect advisories stuck in non-final states >90 days

Design decisions:
- Each check returns a QualityCheckResult with pass/fail and details
- Checks are SQL-based for performance (run against database, not Python)
- Configurable thresholds where applicable (e.g., stalled CVE threshold)
- Designed to be extended with additional checks as needed
"""
from typing import List, Dict, Any
from dataclasses import dataclass


@dataclass
class QualityCheckResult:
    """
    Result of a single quality check.

    Attributes:
        check_name: Unique identifier for the check
        passed: True if check passed, False otherwise
        message: Human-readable summary of the result
        details: Optional dict with additional context (e.g., counts)
    """
    check_name: str
    passed: bool
    message: str
    details: Dict[str, Any] = None


class QualityChecker:
    """
    Runs data quality checks against pipeline outputs.

    Each check method executes a SQL query against the database and returns
    a QualityCheckResult indicating pass/fail status.
    """

    def __init__(self, database):
        """
        Initialize quality checker.

        Args:
            database: Database instance with active connection
        """
        self.db = database

    def run_all_checks(self) -> List[QualityCheckResult]:
        """
        Run all quality checks.

        Returns:
            List of QualityCheckResult objects, one per check
        """
        results = []
        results.append(self.check_no_null_states())
        results.append(self.check_no_orphan_packages())
        results.append(self.check_explanation_completeness())
        results.append(self.check_fixed_has_version())
        results.append(self.check_cve_format())
        results.append(self.check_stalled_cves())
        return results

    def check_no_null_states(self) -> QualityCheckResult:
        """
        Ensure no current advisory has null state.

        Critical check: Every advisory must have an assigned state.
        """
        conn = self.db.connect()
        result = conn.execute("""
            SELECT count(*) FROM advisory_state_history
            WHERE is_current = true AND state IS NULL
        """).fetchone()[0]

        return QualityCheckResult(
            check_name="no_null_states",
            passed=result == 0,
            message=f"{result} advisories with null state" if result > 0 else "All advisories have state",
            details={"null_count": result}
        )

    def check_explanation_completeness(self) -> QualityCheckResult:
        """
        Ensure all current advisories have non-empty explanations.

        Explanations are required for customer-facing outputs.
        """
        conn = self.db.connect()
        result = conn.execute("""
            SELECT count(*) FROM advisory_state_history
            WHERE is_current = true
              AND (explanation IS NULL OR trim(explanation) = '')
        """).fetchone()[0]

        return QualityCheckResult(
            check_name="explanation_completeness",
            passed=result == 0,
            message=f"{result} advisories missing explanation" if result > 0 else "All advisories have explanations",
            details={"missing_count": result}
        )

    def check_fixed_has_version(self) -> QualityCheckResult:
        """
        Ensure advisories in "fixed" state have fixed_version set.

        This is a business rule: if we say it's fixed, we must say which version.
        """
        conn = self.db.connect()
        result = conn.execute("""
            SELECT count(*) FROM advisory_state_history
            WHERE is_current = true
              AND state = 'fixed'
              AND (fixed_version IS NULL OR trim(fixed_version) = '')
        """).fetchone()[0]

        return QualityCheckResult(
            check_name="fixed_has_version",
            passed=result == 0,
            message=f"{result} fixed advisories without version" if result > 0 else "All fixed advisories have version",
            details={"missing_count": result}
        )

    def check_cve_format(self) -> QualityCheckResult:
        """
        Check that all CVE IDs match the expected format: CVE-YYYY-NNNN+.

        Uses SQL SIMILAR TO (regex) for format validation.
        """
        conn = self.db.connect()
        result = conn.execute("""
            SELECT count(*) FROM advisory_state_history
            WHERE is_current = true
              AND cve_id IS NOT NULL
              AND cve_id NOT SIMILAR TO 'CVE-[0-9]{4}-[0-9]{4,}'
        """).fetchone()[0]

        return QualityCheckResult(
            check_name="cve_format",
            passed=result == 0,
            message=f"{result} invalid CVE formats" if result > 0 else "All CVE IDs valid",
            details={"invalid_count": result}
        )

    def check_no_orphan_packages(self) -> QualityCheckResult:
        """
        Placeholder check for package registry validation.

        In production, this would validate that all package names exist in
        a canonical package registry. Not implemented in prototype.
        """
        return QualityCheckResult(
            check_name="no_orphan_packages",
            passed=True,
            message="Check skipped (no package registry in prototype)"
        )

    def check_stalled_cves(self) -> QualityCheckResult:
        """
        Detect CVEs stuck in non-final state for >90 days.

        Non-final states (pending_upstream, under_investigation) should
        eventually resolve. Long-lived non-final states may indicate
        stale data or upstream issues.

        Warning threshold: 10 stalled CVEs
        """
        conn = self.db.connect()
        result = conn.execute("""
            SELECT count(*) FROM advisory_state_history
            WHERE is_current = true
              AND state_type = 'non_final'
              AND effective_from < current_timestamp - interval '90 days'
        """).fetchone()[0]

        return QualityCheckResult(
            check_name="stalled_cves",
            passed=result < 10,  # Warning threshold
            message=f"{result} CVEs stalled >90 days" if result > 0 else "No stalled CVEs",
            details={"stalled_count": result}
        )
