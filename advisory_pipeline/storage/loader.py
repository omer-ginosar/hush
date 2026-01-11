"""
Source observation loader for raw landing zone tables.

This module handles loading normalized observations from source adapters
into DuckDB raw tables. Each source type has a dedicated loader method
that maps SourceObservation fields to the appropriate table schema.

Design decisions:
- Per-source loader methods for explicit field mapping
- DELETE + INSERT pattern for idempotent loads
- JSON serialization for complex fields (raw_payload, references)
- Batch-friendly design (though currently single-record inserts)
"""
import json
from typing import List

from ingestion.base_adapter import SourceObservation
from .database import Database


class SourceLoader:
    """
    Loads observations from adapters into raw landing zone tables.

    Each source has a dedicated loading method that:
    1. Clears previous data for this run_id
    2. Maps SourceObservation fields to table columns
    3. Handles JSON serialization for complex types
    4. Inserts records into the appropriate raw table
    """

    def __init__(self, database: Database):
        """
        Initialize loader with database connection.

        Args:
            database: Database instance to load data into
        """
        self.db = database

    def load_echo_advisories(self, observations: List[SourceObservation], run_id: str) -> int:
        """
        Load Echo advisory observations from data.json.

        Args:
            observations: List of normalized observations from EchoDataAdapter
            run_id: Pipeline run identifier

        Returns:
            Number of records loaded
        """
        conn = self.db.connect()

        # Clear previous run's data for idempotent loads
        conn.execute("DELETE FROM raw_echo_advisories WHERE run_id = ?", [run_id])

        loaded = 0
        for obs in observations:
            conn.execute("""
                INSERT INTO raw_echo_advisories
                (observation_id, cve_id, package_name, observed_at, raw_payload,
                 status, cvss_score, notes, run_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                obs.observation_id,
                obs.cve_id,
                obs.package_name,
                obs.observed_at,
                json.dumps(obs.raw_payload),
                obs.status,
                obs.cvss_score,
                obs.notes,
                run_id
            ])
            loaded += 1

        return loaded

    def load_echo_csv(self, observations: List[SourceObservation], run_id: str) -> int:
        """
        Load Echo CSV override observations.

        Args:
            observations: List of normalized observations from EchoCsvAdapter
            run_id: Pipeline run identifier

        Returns:
            Number of records loaded
        """
        conn = self.db.connect()
        conn.execute("DELETE FROM raw_echo_csv WHERE run_id = ?", [run_id])

        loaded = 0
        for obs in observations:
            conn.execute("""
                INSERT INTO raw_echo_csv
                (observation_id, cve_id, package_name, observed_at, source_updated_at,
                 raw_payload, status, reason, run_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                obs.observation_id,
                obs.cve_id,
                obs.package_name,
                obs.observed_at,
                obs.source_updated_at,
                json.dumps(obs.raw_payload),
                obs.status,
                obs.notes,  # CSV adapter stores reason in notes field
                run_id
            ])
            loaded += 1

        return loaded

    def load_nvd_observations(self, observations: List[SourceObservation], run_id: str) -> int:
        """
        Load NVD CVE observations.

        Args:
            observations: List of normalized observations from NvdAdapter
            run_id: Pipeline run identifier

        Returns:
            Number of records loaded
        """
        conn = self.db.connect()
        conn.execute("DELETE FROM raw_nvd_observations WHERE run_id = ?", [run_id])

        loaded = 0
        for obs in observations:
            conn.execute("""
                INSERT INTO raw_nvd_observations
                (observation_id, cve_id, observed_at, raw_payload, rejection_status,
                 cvss_score, cvss_vector, "references", notes, run_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                obs.observation_id,
                obs.cve_id,
                obs.observed_at,
                json.dumps(obs.raw_payload),
                obs.rejection_status,
                obs.cvss_score,
                obs.cvss_vector,
                json.dumps(obs.references) if obs.references else None,
                obs.notes,
                run_id
            ])
            loaded += 1

        return loaded

    def load_osv_observations(self, observations: List[SourceObservation], run_id: str) -> int:
        """
        Load OSV vulnerability observations.

        Args:
            observations: List of normalized observations from OsvAdapter
            run_id: Pipeline run identifier

        Returns:
            Number of records loaded
        """
        conn = self.db.connect()
        conn.execute("DELETE FROM raw_osv_observations WHERE run_id = ?", [run_id])

        loaded = 0
        for obs in observations:
            conn.execute("""
                INSERT INTO raw_osv_observations
                (observation_id, cve_id, package_name, observed_at, raw_payload,
                 fix_available, fixed_version, "references", notes, run_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                obs.observation_id,
                obs.cve_id,
                obs.package_name,
                obs.observed_at,
                json.dumps(obs.raw_payload),
                obs.fix_available,
                obs.fixed_version,
                json.dumps(obs.references) if obs.references else None,
                obs.notes,
                run_id
            ])
            loaded += 1

        return loaded

    def load_all(
        self,
        echo_advisories: List[SourceObservation],
        echo_csv: List[SourceObservation],
        nvd: List[SourceObservation],
        osv: List[SourceObservation],
        run_id: str
    ) -> dict:
        """
        Load observations from all sources in a single call.

        Args:
            echo_advisories: Observations from EchoDataAdapter
            echo_csv: Observations from EchoCsvAdapter
            nvd: Observations from NvdAdapter
            osv: Observations from OsvAdapter
            run_id: Pipeline run identifier

        Returns:
            Dictionary with counts per source
        """
        return {
            "echo_advisories": self.load_echo_advisories(echo_advisories, run_id),
            "echo_csv": self.load_echo_csv(echo_csv, run_id),
            "nvd": self.load_nvd_observations(nvd, run_id),
            "osv": self.load_osv_observations(osv, run_id)
        }
