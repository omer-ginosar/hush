"""
Storage layer for the CVE advisory pipeline.

This module provides data persistence using DuckDB. State history tracking
is handled by dbt snapshots in Phase 4.

Components:
- Database: Connection management and schema initialization
- SourceLoader: Load source observations into raw landing tables

Usage:
    from storage import Database, SourceLoader

    # Initialize database
    db = Database("advisory_pipeline.duckdb")
    db.initialize_schema()

    # Load source observations
    loader = SourceLoader(db)
    loader.load_echo_advisories(observations, run_id)

Note:
    Advisory state history is managed by dbt snapshots (Phase 4), not Python.
    The advisory_state_history table is created for dbt to populate.
"""

from .database import Database
from .loader import SourceLoader

__all__ = [
    "Database",
    "SourceLoader",
]
