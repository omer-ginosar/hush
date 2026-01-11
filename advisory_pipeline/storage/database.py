"""
Database connection and schema management for the advisory pipeline.

This module provides:
- DuckDB connection lifecycle management
- Raw landing zone tables for source observations
- Advisory state history table (SCD Type 2)
- Pipeline run metadata tracking

Design decisions:
- Using DuckDB instead of SQLite for better dbt compatibility
- JSON columns for storing raw payloads and complex evidence
- SCD Type 2 pattern with effective_from/effective_to timestamps
- Indexed on advisory_id, cve_id, and is_current for query performance
"""
import duckdb
from datetime import datetime
from pathlib import Path
from typing import Optional


class Database:
    """
    Manages DuckDB connection and schema initialization.

    This class is responsible for:
    - Creating and maintaining a single database connection
    - Initializing raw landing zone tables for each source
    - Setting up the advisory_state_history table for SCD2 tracking
    - Providing run ID generation for pipeline execution tracking
    """

    def __init__(self, db_path: str = "advisory_pipeline.duckdb"):
        """
        Initialize database manager.

        Args:
            db_path: Path to DuckDB database file (created if doesn't exist)
        """
        self.db_path = db_path
        self.conn: Optional[duckdb.DuckDBPyConnection] = None

    def connect(self) -> duckdb.DuckDBPyConnection:
        """
        Get or create database connection.

        Returns:
            Active DuckDB connection
        """
        if self.conn is None:
            self.conn = duckdb.connect(self.db_path)
        return self.conn

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None

    def initialize_schema(self):
        """
        Create all required tables if they don't exist.

        Tables created:
        - raw_echo_advisories: Base advisory corpus from Echo
        - raw_echo_csv: Internal analyst overrides
        - raw_nvd_observations: NVD CVE data
        - raw_osv_observations: OSV vulnerability data
        - advisory_state_history: SCD2 state tracking
        - pipeline_runs: Pipeline execution metadata
        """
        conn = self.connect()

        # Raw Echo advisories (from data.json)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS raw_echo_advisories (
                observation_id VARCHAR PRIMARY KEY,
                cve_id VARCHAR,
                package_name VARCHAR,
                observed_at TIMESTAMP,
                raw_payload JSON,
                status VARCHAR,
                cvss_score DOUBLE,
                notes VARCHAR,
                run_id VARCHAR
            )
        """)

        # Raw Echo CSV overrides
        conn.execute("""
            CREATE TABLE IF NOT EXISTS raw_echo_csv (
                observation_id VARCHAR PRIMARY KEY,
                cve_id VARCHAR,
                package_name VARCHAR,
                observed_at TIMESTAMP,
                source_updated_at TIMESTAMP,
                raw_payload JSON,
                status VARCHAR,
                reason VARCHAR,
                run_id VARCHAR
            )
        """)

        # Raw NVD observations
        conn.execute("""
            CREATE TABLE IF NOT EXISTS raw_nvd_observations (
                observation_id VARCHAR PRIMARY KEY,
                cve_id VARCHAR,
                observed_at TIMESTAMP,
                raw_payload JSON,
                rejection_status VARCHAR,
                cvss_score DOUBLE,
                cvss_vector VARCHAR,
                "references" JSON,
                notes VARCHAR,
                run_id VARCHAR
            )
        """)

        # Raw OSV observations
        conn.execute("""
            CREATE TABLE IF NOT EXISTS raw_osv_observations (
                observation_id VARCHAR PRIMARY KEY,
                cve_id VARCHAR,
                package_name VARCHAR,
                observed_at TIMESTAMP,
                raw_payload JSON,
                fix_available BOOLEAN,
                fixed_version VARCHAR,
                "references" JSON,
                notes VARCHAR,
                run_id VARCHAR
            )
        """)

        # Pipeline run metadata
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pipeline_runs (
                run_id VARCHAR PRIMARY KEY,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                status VARCHAR,
                advisories_processed INTEGER,
                state_changes INTEGER,
                errors INTEGER,
                metadata JSON
            )
        """)

        # Advisory state history (SCD Type 2)
        # This table is populated by dbt snapshots in Phase 4, not Python
        # Schema matches dbt snapshot requirements for temporal tracking
        conn.execute("""
            CREATE TABLE IF NOT EXISTS advisory_state_history (
                history_id VARCHAR PRIMARY KEY,
                advisory_id VARCHAR NOT NULL,
                cve_id VARCHAR,
                package_name VARCHAR,
                state VARCHAR NOT NULL,
                state_type VARCHAR,
                fixed_version VARCHAR,
                confidence VARCHAR,
                explanation VARCHAR,
                reason_code VARCHAR,
                evidence JSON,
                decision_rule VARCHAR,
                contributing_sources JSON,
                dissenting_sources JSON,
                effective_from TIMESTAMP NOT NULL,
                effective_to TIMESTAMP,
                is_current BOOLEAN NOT NULL,
                run_id VARCHAR,
                staleness_score DOUBLE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create indexes for query performance
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_ash_advisory
            ON advisory_state_history(advisory_id)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_ash_current
            ON advisory_state_history(is_current)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_ash_cve
            ON advisory_state_history(cve_id)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_ash_effective
            ON advisory_state_history(effective_from, effective_to)
        """)

    def get_current_run_id(self) -> str:
        """
        Generate a unique run ID for this pipeline execution.

        Returns:
            Run ID in format: run_YYYYMMDD_HHMMSS
        """
        return f"run_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
