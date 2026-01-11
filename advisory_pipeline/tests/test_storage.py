"""
Lightweight tests for storage layer.

These tests validate core functionality without heavy mocking:
- Database schema initialization
- Source observation loading
- SCD2 state transitions
- Point-in-time queries
"""
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from storage import Database, SourceLoader, SCD2Manager, AdvisoryState
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


def test_scd2_first_state(temp_db):
    """Test creating first state for an advisory."""
    scd2 = SCD2Manager(temp_db)

    state = AdvisoryState(
        advisory_id="pkg:CVE-2024-0001",
        cve_id="CVE-2024-0001",
        package_name="pkg",
        state="under_investigation",
        state_type="non_final",
        fixed_version=None,
        confidence="low",
        explanation="New CVE under analysis",
        reason_code="NEW_CVE",
        evidence={"source_count": 1},
        decision_rule="R5:under_investigation",
        contributing_sources=["echo_data"],
        dissenting_sources=[],
        staleness_score=0.0
    )

    run_id = "run_test_003"
    changed = scd2.apply_state(state, run_id)

    assert changed is True

    # Verify current state
    current = scd2.get_current_state("pkg:CVE-2024-0001")
    assert current is not None
    assert current["state"] == "under_investigation"
    assert current["is_current"] is True


def test_scd2_state_transition(temp_db):
    """Test state change creates new history record."""
    scd2 = SCD2Manager(temp_db)

    # First state
    state1 = AdvisoryState(
        advisory_id="pkg:CVE-2024-0002",
        cve_id="CVE-2024-0002",
        package_name="pkg",
        state="under_investigation",
        state_type="non_final",
        fixed_version=None,
        confidence="low",
        explanation="New CVE",
        reason_code="NEW_CVE",
        evidence={},
        decision_rule="R5",
        contributing_sources=["echo_data"],
        dissenting_sources=[],
        staleness_score=0.0
    )

    scd2.apply_state(state1, "run_001")

    # Second state (changed)
    state2 = AdvisoryState(
        advisory_id="pkg:CVE-2024-0002",
        cve_id="CVE-2024-0002",
        package_name="pkg",
        state="fixed",
        state_type="final",
        fixed_version="1.2.3",
        confidence="high",
        explanation="Fixed in version 1.2.3",
        reason_code="UPSTREAM_FIX",
        evidence={"fixed_version": "1.2.3"},
        decision_rule="R2",
        contributing_sources=["echo_data", "osv"],
        dissenting_sources=[],
        staleness_score=0.0
    )

    changed = scd2.apply_state(state2, "run_002")

    assert changed is True

    # Verify history
    history = scd2.get_history("pkg:CVE-2024-0002")
    assert len(history) == 2

    # First record should be closed
    assert history[0]["is_current"] is False
    assert history[0]["effective_to"] is not None

    # Second record should be current
    assert history[1]["is_current"] is True
    assert history[1]["effective_to"] is None
    assert history[1]["state"] == "fixed"


def test_scd2_no_change_skip(temp_db):
    """Test that identical state doesn't create new record."""
    scd2 = SCD2Manager(temp_db)

    state = AdvisoryState(
        advisory_id="pkg:CVE-2024-0003",
        cve_id="CVE-2024-0003",
        package_name="pkg",
        state="fixed",
        state_type="final",
        fixed_version="1.0.0",
        confidence="high",
        explanation="Fixed",
        reason_code="UPSTREAM_FIX",
        evidence={},
        decision_rule="R2",
        contributing_sources=["osv"],
        dissenting_sources=[],
        staleness_score=0.0
    )

    # First apply
    changed1 = scd2.apply_state(state, "run_001")
    assert changed1 is True

    # Second apply (same state)
    changed2 = scd2.apply_state(state, "run_002")
    assert changed2 is False

    # Should still have only one record
    history = scd2.get_history("pkg:CVE-2024-0003")
    assert len(history) == 1


def test_scd2_point_in_time_query(temp_db):
    """Test querying historical state at specific time."""
    scd2 = SCD2Manager(temp_db)

    now = datetime.utcnow()

    # State 1
    state1 = AdvisoryState(
        advisory_id="pkg:CVE-2024-0004",
        cve_id="CVE-2024-0004",
        package_name="pkg",
        state="under_investigation",
        state_type="non_final",
        fixed_version=None,
        confidence="low",
        explanation="New",
        reason_code="NEW_CVE",
        evidence={},
        decision_rule="R5",
        contributing_sources=["echo_data"],
        dissenting_sources=[],
        staleness_score=0.0
    )

    scd2.apply_state(state1, "run_001")

    # Wait a bit (simulate time passing)
    import time
    time.sleep(0.1)

    middle_time = datetime.utcnow()

    time.sleep(0.1)

    # State 2
    state2 = AdvisoryState(
        advisory_id="pkg:CVE-2024-0004",
        cve_id="CVE-2024-0004",
        package_name="pkg",
        state="fixed",
        state_type="final",
        fixed_version="2.0.0",
        confidence="high",
        explanation="Fixed",
        reason_code="UPSTREAM_FIX",
        evidence={},
        decision_rule="R2",
        contributing_sources=["osv"],
        dissenting_sources=[],
        staleness_score=0.0
    )

    scd2.apply_state(state2, "run_002")

    # Query at middle time should return state1
    historical = scd2.get_state_at_time("pkg:CVE-2024-0004", middle_time)
    assert historical is not None
    assert historical["state"] == "under_investigation"

    # Query at current time should return state2
    current = scd2.get_current_state("pkg:CVE-2024-0004")
    assert current["state"] == "fixed"
