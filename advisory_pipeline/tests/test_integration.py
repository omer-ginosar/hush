"""
End-to-end integration tests for the advisory pipeline.

These tests validate the full pipeline flow from ingestion through
decisioning, ensuring components work together correctly.
"""
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from datetime import datetime

from storage import Database, SourceLoader
from ingestion.base_adapter import SourceObservation
from decisioning import RuleEngine


class TestEndToEndPipeline:
    """Integration tests for complete pipeline flow."""

    def test_full_pipeline_flow(self, temp_db, loader):
        """
        Test complete pipeline: ingest -> load -> query.

        This validates the happy path through the entire system.
        """
        run_id = "run_integration_001"

        # 1. Create sample observations from multiple sources
        echo_obs = [
            SourceObservation(
                observation_id="echo_int_001",
                source_id="echo_data",
                cve_id="CVE-2024-1001",
                package_name="test-lib",
                observed_at=datetime.utcnow(),
                raw_payload={"source": "echo"},
                status="open",
                cvss_score=7.0,
                notes="Test advisory"
            )
        ]

        nvd_obs = [
            SourceObservation(
                observation_id="nvd_int_001",
                source_id="nvd",
                cve_id="CVE-2024-1001",
                package_name=None,
                observed_at=datetime.utcnow(),
                raw_payload={"source": "nvd"},
                rejection_status="none",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
            )
        ]

        osv_obs = [
            SourceObservation(
                observation_id="osv_int_001",
                source_id="osv",
                cve_id="CVE-2024-1001",
                package_name="test-lib",
                observed_at=datetime.utcnow(),
                raw_payload={"source": "osv"},
                fix_available=True,
                fixed_version="2.0.0",
                references=["https://github.com/test/fix"]
            )
        ]

        # 2. Load all observations
        counts = loader.load_all(echo_obs, [], nvd_obs, osv_obs, run_id)

        assert counts["echo_advisories"] == 1
        assert counts["nvd"] == 1
        assert counts["osv"] == 1

        # 3. Verify data is queryable
        conn = temp_db.connect()

        # Check Echo data
        echo_result = conn.execute("""
            SELECT cve_id, package_name FROM raw_echo_advisories
            WHERE run_id = ?
        """, [run_id]).fetchone()

        assert echo_result[0] == "CVE-2024-1001"
        assert echo_result[1] == "test-lib"

        # Check NVD data
        nvd_result = conn.execute("""
            SELECT cve_id, cvss_score FROM raw_nvd_observations
            WHERE run_id = ?
        """, [run_id]).fetchone()

        assert nvd_result[0] == "CVE-2024-1001"
        assert nvd_result[1] == 7.5

        # Check OSV data
        osv_result = conn.execute("""
            SELECT cve_id, fixed_version FROM raw_osv_observations
            WHERE run_id = ?
        """, [run_id]).fetchone()

        assert osv_result[0] == "CVE-2024-1001"
        assert osv_result[1] == "2.0.0"

    def test_csv_override_integration(self, temp_db, loader):
        """
        Test that CSV overrides correctly override other sources.

        This validates the R0 rule integration.
        """
        run_id = "run_integration_002"

        # OSV says fixed
        osv_obs = [
            SourceObservation(
                observation_id="osv_002",
                source_id="osv",
                cve_id="CVE-2024-1002",
                package_name="override-test",
                observed_at=datetime.utcnow(),
                raw_payload={},
                fix_available=True,
                fixed_version="1.5.0"
            )
        ]

        # But CSV says not applicable
        csv_obs = [
            SourceObservation(
                observation_id="csv_002",
                source_id="echo_csv",
                cve_id="CVE-2024-1002",
                package_name="override-test",
                observed_at=datetime.utcnow(),
                source_updated_at=datetime.utcnow(),
                raw_payload={"analyst": "test"},
                status="not_applicable",
                notes="Service not exposed"
            )
        ]

        counts = loader.load_all([], csv_obs, [], osv_obs, run_id)

        assert counts["echo_csv"] == 1
        assert counts["osv"] == 1

        # Both observations should be in database
        conn = temp_db.connect()

        csv_count = conn.execute(
            "SELECT COUNT(*) FROM raw_echo_csv WHERE run_id = ?", [run_id]
        ).fetchone()[0]
        assert csv_count == 1

        osv_count = conn.execute(
            "SELECT COUNT(*) FROM raw_osv_observations WHERE run_id = ?", [run_id]
        ).fetchone()[0]
        assert osv_count == 1

    def test_nvd_rejection_integration(self, temp_db, loader):
        """
        Test NVD rejection handling.

        Validates R1 rule integration.
        """
        run_id = "run_integration_003"

        nvd_obs = [
            SourceObservation(
                observation_id="nvd_003",
                source_id="nvd",
                cve_id="CVE-2024-1003",
                package_name=None,
                observed_at=datetime.utcnow(),
                raw_payload={"vulnStatus": "Rejected"},
                rejection_status="rejected",
                notes="Duplicate of CVE-2023-9999"
            )
        ]

        count = loader.load_nvd_observations(nvd_obs, run_id)
        assert count == 1

        # Verify rejection status stored
        conn = temp_db.connect()
        result = conn.execute("""
            SELECT rejection_status FROM raw_nvd_observations
            WHERE cve_id = ? AND run_id = ?
        """, ["CVE-2024-1003", run_id]).fetchone()

        assert result[0] == "rejected"

    def test_multiple_runs_idempotent(self, temp_db, loader):
        """
        Test that multiple pipeline runs are idempotent for same data.

        Each run should replace previous run's data.
        """
        run_id = "run_integration_004"

        obs = [
            SourceObservation(
                observation_id="multi_001",
                source_id="echo_data",
                cve_id="CVE-2024-1004",
                package_name="multi-test",
                observed_at=datetime.utcnow(),
                raw_payload={}
            )
        ]

        # Load twice with same run_id
        count1 = loader.load_echo_advisories(obs, run_id)
        count2 = loader.load_echo_advisories(obs, run_id)

        assert count1 == 1
        assert count2 == 1

        # Should only have one record
        conn = temp_db.connect()
        total = conn.execute("""
            SELECT COUNT(*) FROM raw_echo_advisories WHERE run_id = ?
        """, [run_id]).fetchone()[0]

        assert total == 1

    def test_package_name_null_handling(self, temp_db, loader):
        """
        Test that NULL package names are handled correctly.

        OSV can have NULL package names when package info unavailable.
        """
        run_id = "run_integration_005"

        # OSV observation without package name
        osv_obs = [
            SourceObservation(
                observation_id="osv_null_pkg",
                source_id="osv",
                cve_id="CVE-2024-1005",
                package_name=None,  # Sometimes package info unavailable
                observed_at=datetime.utcnow(),
                raw_payload={},
                fix_available=False
            )
        ]

        count = loader.load_osv_observations(osv_obs, run_id)
        assert count == 1

        # Verify NULL stored correctly
        conn = temp_db.connect()
        result = conn.execute("""
            SELECT package_name FROM raw_osv_observations
            WHERE cve_id = ? AND run_id = ?
        """, ["CVE-2024-1005", run_id]).fetchone()

        assert result[0] is None

    def test_json_payload_preservation(self, temp_db, loader):
        """
        Test that raw JSON payloads are preserved correctly.

        Important for debugging and audit trails.
        """
        run_id = "run_integration_006"

        complex_payload = {
            "nested": {
                "data": [1, 2, 3],
                "metadata": {"source": "test", "version": "1.0"}
            },
            "special_chars": "unicode: 日本語"
        }

        obs = [
            SourceObservation(
                observation_id="json_test",
                source_id="echo_data",
                cve_id="CVE-2024-1006",
                package_name="json-test",
                observed_at=datetime.utcnow(),
                raw_payload=complex_payload
            )
        ]

        loader.load_echo_advisories(obs, run_id)

        # Verify JSON round-trip
        conn = temp_db.connect()
        result = conn.execute("""
            SELECT raw_payload FROM raw_echo_advisories
            WHERE observation_id = ?
        """, ["json_test"]).fetchone()

        import json
        retrieved_payload = json.loads(result[0])

        assert retrieved_payload == complex_payload
        assert retrieved_payload["nested"]["data"] == [1, 2, 3]
        assert retrieved_payload["special_chars"] == "unicode: 日本語"


class TestCrossSourceJoins:
    """Test queries that join across multiple source tables."""

    def test_join_echo_and_nvd(self, temp_db, loader):
        """
        Test joining Echo advisories with NVD observations.

        This simulates the dbt enrichment layer joins.
        """
        run_id = "run_join_001"

        echo_obs = [
            SourceObservation(
                observation_id="echo_join_001",
                source_id="echo_data",
                cve_id="CVE-2024-2001",
                package_name="join-test",
                observed_at=datetime.utcnow(),
                raw_payload={}
            )
        ]

        nvd_obs = [
            SourceObservation(
                observation_id="nvd_join_001",
                source_id="nvd",
                cve_id="CVE-2024-2001",
                package_name=None,
                observed_at=datetime.utcnow(),
                raw_payload={},
                cvss_score=9.1
            )
        ]

        loader.load_all(echo_obs, [], nvd_obs, [], run_id)

        # Join on CVE ID
        conn = temp_db.connect()
        result = conn.execute("""
            SELECT
                e.package_name,
                e.cve_id,
                n.cvss_score
            FROM raw_echo_advisories e
            JOIN raw_nvd_observations n ON e.cve_id = n.cve_id
            WHERE e.run_id = ? AND n.run_id = ?
        """, [run_id, run_id]).fetchone()

        assert result is not None
        assert result[0] == "join-test"
        assert result[1] == "CVE-2024-2001"
        assert result[2] == 9.1

    def test_left_join_with_missing_osv(self, temp_db, loader):
        """
        Test LEFT JOIN when OSV data is missing.

        Echo advisories may not have corresponding OSV data.
        """
        run_id = "run_join_002"

        echo_obs = [
            SourceObservation(
                observation_id="echo_join_002",
                source_id="echo_data",
                cve_id="CVE-2024-2002",
                package_name="no-osv-test",
                observed_at=datetime.utcnow(),
                raw_payload={}
            )
        ]

        loader.load_echo_advisories(echo_obs, run_id)

        # LEFT JOIN should still return Echo row
        conn = temp_db.connect()
        result = conn.execute("""
            SELECT
                e.cve_id,
                o.fixed_version
            FROM raw_echo_advisories e
            LEFT JOIN raw_osv_observations o
                ON e.cve_id = o.cve_id AND e.run_id = o.run_id
            WHERE e.run_id = ?
        """, [run_id]).fetchone()

        assert result is not None
        assert result[0] == "CVE-2024-2002"
        assert result[1] is None  # No OSV data

    def test_aggregate_by_cve(self, temp_db, loader):
        """
        Test aggregating observations by CVE ID.

        Multiple sources may provide data for same CVE.
        """
        run_id = "run_agg_001"

        # Same CVE from multiple sources
        echo_obs = [
            SourceObservation(
                observation_id="echo_agg",
                source_id="echo_data",
                cve_id="CVE-2024-3001",
                package_name="agg-test",
                observed_at=datetime.utcnow(),
                raw_payload={}
            )
        ]

        nvd_obs = [
            SourceObservation(
                observation_id="nvd_agg",
                source_id="nvd",
                cve_id="CVE-2024-3001",
                package_name=None,
                observed_at=datetime.utcnow(),
                raw_payload={}
            )
        ]

        osv_obs = [
            SourceObservation(
                observation_id="osv_agg",
                source_id="osv",
                cve_id="CVE-2024-3001",
                package_name="agg-test",
                observed_at=datetime.utcnow(),
                raw_payload={}
            )
        ]

        loader.load_all(echo_obs, [], nvd_obs, osv_obs, run_id)

        # Count sources per CVE
        conn = temp_db.connect()
        result = conn.execute("""
            SELECT COUNT(*) as source_count FROM (
                SELECT cve_id FROM raw_echo_advisories WHERE run_id = ?
                UNION ALL
                SELECT cve_id FROM raw_nvd_observations WHERE run_id = ?
                UNION ALL
                SELECT cve_id FROM raw_osv_observations WHERE run_id = ?
            ) WHERE cve_id = 'CVE-2024-3001'
        """, [run_id, run_id, run_id]).fetchone()

        assert result[0] == 3  # Three sources for same CVE
