"""
Metrics collection for pipeline runs.

This module provides RunMetrics, a dataclass that tracks all observability
metrics for a single pipeline execution including:
- Counts of advisories processed and state changes
- State distribution across the advisory corpus
- State transitions that occurred
- Which rules fired and how often
- Source health indicators
- Quality issues encountered

Design decisions:
- Single metrics object per run for simplicity
- Defaultdict used for automatic initialization of counters
- Transition tracking uses tuple keys (from_state, to_state)
- Serializable to_dict() for storage in pipeline_runs table
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Any
from collections import defaultdict


@dataclass
class RunMetrics:
    """
    Metrics for a single pipeline run.

    Tracks counts, state changes, rule firing, source health, and quality issues.
    Designed to be serialized to JSON for storage in the pipeline_runs table.
    """
    run_id: str
    started_at: datetime
    completed_at: datetime = None

    # Core counts
    advisories_total: int = 0
    advisories_processed: int = 0
    state_changes: int = 0
    errors: int = 0

    # State distribution (current snapshot)
    state_counts: Dict[str, int] = field(default_factory=dict)

    # State transitions in this run
    # Key: (from_state, to_state), Value: count
    transitions: Dict[tuple, int] = field(default_factory=lambda: defaultdict(int))

    # Rules fired in this run
    # Key: rule_id (e.g., "R0:csv_override"), Value: count
    rules_fired: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # Source health status
    # Key: source_id, Value: dict with health status
    source_health: Dict[str, Dict] = field(default_factory=dict)

    # Quality issues encountered
    quality_issues: List[Dict] = field(default_factory=list)

    def record_transition(self, from_state: str, to_state: str):
        """
        Record a state transition.

        Only counts as a change if from_state != to_state.
        Tracks the transition for reporting.

        Args:
            from_state: Previous state (or "unknown" for new advisories)
            to_state: New state assigned by rules
        """
        if from_state != to_state:
            self.transitions[(from_state, to_state)] += 1
            self.state_changes += 1

    def record_rule_fired(self, rule_id: str):
        """
        Record that a decision rule was used.

        Args:
            rule_id: Rule identifier (e.g., "R0:csv_override")
        """
        self.rules_fired[rule_id] += 1

    def record_error(self, error: str, context: Dict = None):
        """
        Record an error encountered during the run.

        Args:
            error: Error message
            context: Optional dict with additional context (e.g., advisory_id)
        """
        self.errors += 1
        self.quality_issues.append({
            "type": "error",
            "message": error,
            "context": context or {}
        })

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert metrics to dictionary for JSON serialization.

        Transitions dict keys are converted from tuples to strings for JSON compatibility.
        Defaultdicts are converted to regular dicts.

        Returns:
            Dictionary representation suitable for JSON storage
        """
        return {
            "run_id": self.run_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "advisories_total": self.advisories_total,
            "advisories_processed": self.advisories_processed,
            "state_changes": self.state_changes,
            "errors": self.errors,
            "state_counts": self.state_counts,
            "transitions": {f"{k[0]}->{k[1]}": v for k, v in self.transitions.items()},
            "rules_fired": dict(self.rules_fired),
            "source_health": self.source_health,
            "quality_issues": self.quality_issues
        }
