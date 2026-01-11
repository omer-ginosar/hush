"""
Storage layer for the CVE advisory pipeline.

This module provides data persistence using DuckDB with SCD Type 2 history tracking.

Components:
- Database: Connection management and schema initialization
- SourceLoader: Load source observations into raw landing tables
- SCD2Manager: Manage advisory state history with temporal tracking
- AdvisoryState: Data class for advisory state snapshots

Usage:
    from storage import Database, SourceLoader, SCD2Manager, AdvisoryState

    # Initialize database
    db = Database("advisory_pipeline.duckdb")
    db.initialize_schema()

    # Load source observations
    loader = SourceLoader(db)
    loader.load_echo_advisories(observations, run_id)

    # Manage state history
    scd2 = SCD2Manager(db)
    state = AdvisoryState(...)
    scd2.apply_state(state, run_id)
"""

from .database import Database
from .loader import SourceLoader
from .scd2_manager import SCD2Manager, AdvisoryState

__all__ = [
    "Database",
    "SourceLoader",
    "SCD2Manager",
    "AdvisoryState",
]
