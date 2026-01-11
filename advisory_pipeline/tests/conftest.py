"""
Shared pytest fixtures for advisory pipeline tests.

This module provides reusable fixtures that simplify test setup
and reduce code duplication across test modules.
"""
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from storage import Database, SourceLoader
from ingestion.base_adapter import SourceObservation


@pytest.fixture
def temp_db():
    """
    Create a temporary in-memory database for testing.

    Yields:
        Database instance with schema initialized

    Cleanup:
        Automatically closes connection and removes file after test
    """
    with tempfile.NamedTemporaryFile(suffix=".duckdb", delete=True) as f:
        db_path = f.name

    db = Database(db_path)
    db.initialize_schema()
    yield db
    db.close()

    # Cleanup
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def sample_echo_observations():
    """
    Sample Echo advisory observations for testing.

    Returns:
        List of SourceObservation objects representing Echo advisories
    """
    return [
        SourceObservation(
            observation_id="echo_001",
            source_id="echo_data",
            cve_id="CVE-2024-0001",
            package_name="example-package",
            observed_at=datetime.utcnow(),
            raw_payload={"test": "data"},
            status="open",
            cvss_score=7.5,
            notes="Buffer overflow vulnerability"
        ),
        SourceObservation(
            observation_id="echo_002",
            source_id="echo_data",
            cve_id="CVE-2024-0002",
            package_name="db-handler",
            observed_at=datetime.utcnow(),
            raw_payload={"test": "data"},
            status="open",
            cvss_score=9.8,
            notes="SQL injection vulnerability"
        ),
    ]


@pytest.fixture
def sample_nvd_observations():
    """
    Sample NVD observations for testing.

    Returns:
        List of SourceObservation objects from NVD
    """
    return [
        SourceObservation(
            observation_id="nvd_001",
            source_id="nvd",
            cve_id="CVE-2024-0001",
            package_name=None,
            observed_at=datetime.utcnow(),
            raw_payload={"cve": {"id": "CVE-2024-0001"}},
            rejection_status="none",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            references=["https://example.com/advisory/1"]
        ),
        SourceObservation(
            observation_id="nvd_002",
            source_id="nvd",
            cve_id="CVE-2024-0002",
            package_name=None,
            observed_at=datetime.utcnow(),
            raw_payload={"cve": {"id": "CVE-2024-0002"}},
            rejection_status="rejected",
            cvss_score=None,
            cvss_vector=None,
            references=[]
        ),
    ]


@pytest.fixture
def sample_osv_observations():
    """
    Sample OSV observations for testing.

    Returns:
        List of SourceObservation objects from OSV
    """
    return [
        SourceObservation(
            observation_id="osv_001",
            source_id="osv",
            cve_id="CVE-2024-0001",
            package_name="example-package",
            observed_at=datetime.utcnow(),
            raw_payload={"id": "GHSA-0001-0001-0001"},
            fix_available=True,
            fixed_version="1.2.3",
            references=["https://github.com/example/package/commit/abc123"],
            notes="Buffer overflow fixed in 1.2.3"
        ),
    ]


@pytest.fixture
def sample_csv_observations():
    """
    Sample CSV override observations for testing.

    Returns:
        List of SourceObservation objects from analyst CSV
    """
    return [
        SourceObservation(
            observation_id="csv_001",
            source_id="echo_csv",
            cve_id="CVE-2024-0003",
            package_name="parser-lib",
            observed_at=datetime.utcnow(),
            source_updated_at=datetime.utcnow(),
            raw_payload={"analyst": "john.doe"},
            status="not_applicable",
            notes="Not applicable - service not exposed"
        ),
    ]


@pytest.fixture
def loader(temp_db):
    """
    Create a SourceLoader instance for testing.

    Args:
        temp_db: Temporary database fixture

    Returns:
        SourceLoader instance connected to temp database
    """
    return SourceLoader(temp_db)
