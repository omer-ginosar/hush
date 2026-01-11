"""
SCD Type 2 (Slowly Changing Dimension) state management for advisory history.

This module implements the SCD Type 2 pattern for tracking advisory state changes
over time. Each state change creates a new history record while closing the previous
one with an effective_to timestamp.

Key concepts:
- effective_from: When this state became active
- effective_to: When this state was superseded (NULL if current)
- is_current: Boolean flag for the active state (only one per advisory)
- history_id: Unique identifier for each history record

Design decisions:
- Detect changes by comparing state, fixed_version, confidence, reason_code
- Use explicit state comparison rather than hash-based change detection
- Generate stable history IDs from advisory_id + timestamp
- Support point-in-time queries for historical state reconstruction
"""
import hashlib
import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

from .database import Database


@dataclass
class AdvisoryState:
    """
    Complete state snapshot for an advisory.

    This represents a decision made by the rule engine about an advisory's
    current status. When this state differs from the previous state,
    a new SCD2 history record is created.
    """
    advisory_id: str
    cve_id: str
    package_name: str
    state: str  # fixed | not_applicable | wont_fix | pending_upstream | under_investigation
    state_type: str  # final | non_final
    fixed_version: Optional[str]
    confidence: str  # high | medium | low
    explanation: str
    reason_code: str  # CSV_OVERRIDE | NVD_REJECTED | UPSTREAM_FIX | etc.
    evidence: Dict[str, Any]
    decision_rule: str  # R0:csv_override | R1:nvd_rejected | etc.
    contributing_sources: List[str]
    dissenting_sources: List[str]
    staleness_score: float


class SCD2Manager:
    """
    Manages SCD Type 2 operations for advisory state history.

    Operations:
    1. get_current_state: Retrieve the active state for an advisory
    2. has_state_changed: Compare new state with current to detect changes
    3. apply_state: Write new state, managing history records
    4. get_state_at_time: Point-in-time query for historical state
    5. get_history: Full change history for an advisory
    """

    def __init__(self, database: Database):
        """
        Initialize SCD2 manager.

        Args:
            database: Database instance for state persistence
        """
        self.db = database

    def get_current_state(self, advisory_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the current active state for an advisory.

        Args:
            advisory_id: Unique advisory identifier (package:CVE)

        Returns:
            Dictionary of current state fields, or None if no state exists
        """
        conn = self.db.connect()
        result = conn.execute("""
            SELECT * FROM advisory_state_history
            WHERE advisory_id = ? AND is_current = TRUE
        """, [advisory_id]).fetchone()

        if result:
            columns = [desc[0] for desc in conn.description]
            return dict(zip(columns, result))
        return None

    def has_state_changed(
        self,
        current: Optional[Dict[str, Any]],
        new_state: AdvisoryState
    ) -> bool:
        """
        Determine if state has changed enough to warrant a new history record.

        Changes that trigger new record:
        - state changed (e.g., pending_upstream -> fixed)
        - fixed_version changed (version update)
        - confidence changed (signal strength change)
        - reason_code changed (different decision rule)

        Args:
            current: Current state from database (None if first state)
            new_state: New state from decision engine

        Returns:
            True if a new history record should be created
        """
        if current is None:
            return True

        # Compare fields that matter for history tracking
        if current["state"] != new_state.state:
            return True

        if current["fixed_version"] != new_state.fixed_version:
            return True

        if current["confidence"] != new_state.confidence:
            return True

        if current["reason_code"] != new_state.reason_code:
            return True

        return False

    def apply_state(self, new_state: AdvisoryState, run_id: str) -> bool:
        """
        Apply new state, managing SCD2 history.

        If state has changed:
        1. Close current record (set is_current=FALSE, effective_to=now)
        2. Insert new record (is_current=TRUE, effective_from=now)

        If state hasn't changed:
        - No action taken (skip)

        Args:
            new_state: New advisory state from decision engine
            run_id: Pipeline run identifier

        Returns:
            True if a new history record was created, False if skipped
        """
        conn = self.db.connect()
        current = self.get_current_state(new_state.advisory_id)

        if not self.has_state_changed(current, new_state):
            return False

        now = datetime.utcnow()

        # Close current record if exists
        if current:
            conn.execute("""
                UPDATE advisory_state_history
                SET is_current = FALSE, effective_to = ?
                WHERE advisory_id = ? AND is_current = TRUE
            """, [now, new_state.advisory_id])

        # Generate stable history ID
        history_id = hashlib.md5(
            f"{new_state.advisory_id}:{now.isoformat()}".encode()
        ).hexdigest()[:16]

        # Insert new current record
        conn.execute("""
            INSERT INTO advisory_state_history
            (history_id, advisory_id, cve_id, package_name, state, state_type,
             fixed_version, confidence, explanation, reason_code, evidence,
             decision_rule, contributing_sources, dissenting_sources,
             effective_from, effective_to, is_current, run_id, staleness_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, TRUE, ?, ?)
        """, [
            history_id,
            new_state.advisory_id,
            new_state.cve_id,
            new_state.package_name,
            new_state.state,
            new_state.state_type,
            new_state.fixed_version,
            new_state.confidence,
            new_state.explanation,
            new_state.reason_code,
            json.dumps(new_state.evidence),
            new_state.decision_rule,
            json.dumps(new_state.contributing_sources),
            json.dumps(new_state.dissenting_sources),
            now,
            run_id,
            new_state.staleness_score
        ])

        return True

    def get_state_at_time(
        self,
        advisory_id: str,
        point_in_time: datetime
    ) -> Optional[Dict[str, Any]]:
        """
        Point-in-time query: Get advisory state as it was at a specific time.

        This enables historical analysis and audit trails by querying
        what the advisory state was at any past moment.

        Args:
            advisory_id: Advisory identifier
            point_in_time: Timestamp to query

        Returns:
            State as of that time, or None if advisory didn't exist
        """
        conn = self.db.connect()
        result = conn.execute("""
            SELECT * FROM advisory_state_history
            WHERE advisory_id = ?
              AND effective_from <= ?
              AND (effective_to IS NULL OR effective_to > ?)
        """, [advisory_id, point_in_time, point_in_time]).fetchone()

        if result:
            columns = [desc[0] for desc in conn.description]
            return dict(zip(columns, result))
        return None

    def get_history(self, advisory_id: str) -> List[Dict[str, Any]]:
        """
        Get complete change history for an advisory, ordered chronologically.

        Args:
            advisory_id: Advisory identifier

        Returns:
            List of all state records, oldest first
        """
        conn = self.db.connect()
        results = conn.execute("""
            SELECT * FROM advisory_state_history
            WHERE advisory_id = ?
            ORDER BY effective_from ASC
        """, [advisory_id]).fetchall()

        columns = [desc[0] for desc in conn.description]
        return [dict(zip(columns, row)) for row in results]

    def get_all_current_states(self) -> List[Dict[str, Any]]:
        """
        Get all current advisory states.

        Useful for generating the full advisory_current.json output.

        Returns:
            List of all current state records
        """
        conn = self.db.connect()
        results = conn.execute("""
            SELECT * FROM advisory_state_history
            WHERE is_current = TRUE
            ORDER BY advisory_id
        """).fetchall()

        columns = [desc[0] for desc in conn.description]
        return [dict(zip(columns, row)) for row in results]

    def count_state_changes(self, run_id: str) -> int:
        """
        Count how many state changes occurred in a specific pipeline run.

        Args:
            run_id: Pipeline run identifier

        Returns:
            Number of new history records created in this run
        """
        conn = self.db.connect()
        result = conn.execute("""
            SELECT COUNT(*) FROM advisory_state_history
            WHERE run_id = ?
        """, [run_id]).fetchone()

        return result[0] if result else 0
