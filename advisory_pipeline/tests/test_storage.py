"""
Lightweight tests for storage layer.

These tests validate core functionality without heavy mocking:
- Database schema initialization
- Source observation loading
- Loader idempotency

Note: State history tracking is handled by dbt snapshots (Phase 4).
"""
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from storage import Database, SourceLoader
from ingestion.base_adapter import SourceObservation


@pytest.fixture
def temp_db():
    """Temporary database for testing."""
    # Create temp file and delete it immediately
    # DuckDB will create the actual database file
    with tempfile.NamedTemporaryFile(suffix=".duckdb", delete=True) as f:
        db_path = f.name

    db = Database(db_path)
    db.initialize_schema()
    yield db
    db.close()

    # Cleanup
    Path(db_path).unlink(missing_ok=True)


def test_database_initialization(temp_db):
    """Verify database schema is created correctly."""
    conn = temp_db.connect()

    # Check all expected tables exist
    tables = conn.execute("""
        SELECT table_name FROM information_schema.tables
        WHERE table_schema = 'main'
    """).fetchall()

    table_names = {t[0] for t in tables}

    assert "raw_echo_advisories" in table_names
    assert "raw_echo_csv" in table_names
    assert "raw_nvd_observations" in table_names
    assert "raw_osv_observations" in table_names
    assert "advisory_state_history" in table_names
    assert "pipeline_runs" in table_names


def test_run_id_generation(temp_db):
    """Verify run ID format."""
    run_id = temp_db.get_current_run_id()
    assert run_id.startswith("run_")
    assert len(run_id) == 19  # run_YYYYMMDD_HHMMSS


def test_loader_echo_advisories(temp_db):
    """Test loading Echo advisories."""
    loader = SourceLoader(temp_db)

    observations = [
        SourceObservation(
            observation_id="obs_001",
            source_id="echo_data",
            cve_id="CVE-2024-0001",
            package_name="test-package",
            observed_at=datetime.utcnow(),
            raw_payload={"test": "data"},
            status="open",
            cvss_score=7.5,
            notes="Test advisory"
        )
    ]

    run_id = "run_test_001"
    count = loader.load_echo_advisories(observations, run_id)

    assert count == 1

    # Verify data was loaded
    conn = temp_db.connect()
    result = conn.execute("""
        SELECT * FROM raw_echo_advisories WHERE run_id = ?
    """, [run_id]).fetchall()

    assert len(result) == 1


def test_loader_idempotency(temp_db):
    """Test that loading twice with same run_id replaces data."""
    loader = SourceLoader(temp_db)
    run_id = "run_test_002"

    obs1 = [SourceObservation(
        observation_id="obs_001",
        source_id="echo_data",
        cve_id="CVE-2024-0001",
        package_name="pkg1",
        observed_at=datetime.utcnow(),
        raw_payload={}
    )]

    obs2 = [SourceObservation(
        observation_id="obs_002",
        source_id="echo_data",
        cve_id="CVE-2024-0002",
        package_name="pkg2",
        observed_at=datetime.utcnow(),
        raw_payload={}
    )]

    # Load first batch
    loader.load_echo_advisories(obs1, run_id)

    # Load second batch with same run_id
    loader.load_echo_advisories(obs2, run_id)

    # Should only have second batch
    conn = temp_db.connect()
    result = conn.execute("""
        SELECT observation_id FROM raw_echo_advisories WHERE run_id = ?
    """, [run_id]).fetchall()

    assert len(result) == 1
    assert result[0][0] == "obs_002"


def test_loader_all_sources(temp_db):
    """Test loading observations from all sources."""
    loader = SourceLoader(temp_db)
    run_id = "run_test_003"

    echo_obs = [SourceObservation(
        observation_id="echo_001",
        source_id="echo_data",
        cve_id="CVE-2024-0001",
        package_name="pkg1",
        observed_at=datetime.utcnow(),
        raw_payload={}
    )]

    csv_obs = [SourceObservation(
        observation_id="csv_001",
        source_id="echo_csv",
        cve_id="CVE-2024-0002",
        package_name="pkg2",
        observed_at=datetime.utcnow(),
        raw_payload={}
    )]

    nvd_obs = [SourceObservation(
        observation_id="nvd_001",
        source_id="nvd",
        cve_id="CVE-2024-0003",
        package_name=None,
        observed_at=datetime.utcnow(),
        raw_payload={}
    )]

    osv_obs = [SourceObservation(
        observation_id="osv_001",
        source_id="osv",
        cve_id="CVE-2024-0004",
        package_name="pkg4",
        observed_at=datetime.utcnow(),
        raw_payload={}
    )]

    # Load all sources
    counts = loader.load_all(echo_obs, csv_obs, nvd_obs, osv_obs, run_id)

    # Verify counts
    assert counts["echo_advisories"] == 1
    assert counts["echo_csv"] == 1
    assert counts["nvd"] == 1
    assert counts["osv"] == 1

    # Verify data in each table
    conn = temp_db.connect()

    echo_result = conn.execute(
        "SELECT COUNT(*) FROM raw_echo_advisories WHERE run_id = ?", [run_id]
    ).fetchone()[0]
    assert echo_result == 1

    csv_result = conn.execute(
        "SELECT COUNT(*) FROM raw_echo_csv WHERE run_id = ?", [run_id]
    ).fetchone()[0]
    assert csv_result == 1

    nvd_result = conn.execute(
        "SELECT COUNT(*) FROM raw_nvd_observations WHERE run_id = ?", [run_id]
    ).fetchone()[0]
    assert nvd_result == 1

    osv_result = conn.execute(
        "SELECT COUNT(*) FROM raw_osv_observations WHERE run_id = ?", [run_id]
    ).fetchone()[0]
    assert osv_result == 1
