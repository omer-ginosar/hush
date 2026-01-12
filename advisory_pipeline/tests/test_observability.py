"""
Lightweight validation tests for the observability layer.

These tests verify:
- RunMetrics tracks transitions and rule firing correctly
- RunMetrics serializes to dict properly
- QualityChecker runs without errors on empty database
- RunReporter generates valid Markdown output

Not comprehensive unit tests - just sanity checks to ensure
the observability layer can be integrated into the pipeline.
"""
import pytest
from datetime import datetime
from pathlib import Path
import tempfile

from observability import RunMetrics, QualityChecker, QualityCheckResult, RunReporter
from storage.database import Database


def test_run_metrics_tracks_transitions():
    """Verify RunMetrics correctly tracks state transitions."""
    metrics = RunMetrics(run_id="test_run", started_at=datetime.utcnow())

    # Record some transitions
    metrics.record_transition("unknown", "pending_upstream")
    metrics.record_transition("pending_upstream", "fixed")
    metrics.record_transition("fixed", "fixed")  # No change

    assert metrics.state_changes == 2  # Only first two count
    assert metrics.transitions[("unknown", "pending_upstream")] == 1
    assert metrics.transitions[("pending_upstream", "fixed")] == 1


def test_run_metrics_tracks_rules():
    """Verify RunMetrics correctly tracks rule firing."""
    metrics = RunMetrics(run_id="test_run", started_at=datetime.utcnow())

    metrics.record_rule_fired("R0:csv_override")
    metrics.record_rule_fired("R2:upstream_fix")
    metrics.record_rule_fired("R2:upstream_fix")

    assert metrics.rules_fired["R0:csv_override"] == 1
    assert metrics.rules_fired["R2:upstream_fix"] == 2


def test_run_metrics_serialization():
    """Verify RunMetrics can be serialized to dict."""
    metrics = RunMetrics(
        run_id="test_run",
        started_at=datetime(2024, 1, 15, 12, 0, 0),
        completed_at=datetime(2024, 1, 15, 12, 5, 30)
    )

    metrics.advisories_total = 100
    metrics.advisories_processed = 98
    metrics.record_transition("unknown", "fixed")

    data = metrics.to_dict()

    assert data["run_id"] == "test_run"
    assert data["advisories_total"] == 100
    assert data["advisories_processed"] == 98
    assert data["state_changes"] == 1  # One transition recorded
    assert "unknown->fixed" in data["transitions"]
    assert isinstance(data["started_at"], str)  # ISO format


def test_quality_checker_runs_on_empty_db():
    """Verify QualityChecker can run on empty database."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db = Database(f"{tmpdir}/test.duckdb")
        db.initialize_schema()

        checker = QualityChecker(db)
        results = checker.run_all_checks()

        # Should return results for all checks
        assert len(results) == 6

        # All results should be QualityCheckResult instances
        for result in results:
            assert isinstance(result, QualityCheckResult)
            assert result.check_name
            assert isinstance(result.passed, bool)
            assert result.message

        db.close()


def test_quality_check_result_structure():
    """Verify QualityCheckResult has expected fields."""
    result = QualityCheckResult(
        check_name="test_check",
        passed=True,
        message="All good",
        details={"count": 42}
    )

    assert result.check_name == "test_check"
    assert result.passed is True
    assert result.message == "All good"
    assert result.details["count"] == 42


def test_reporter_generates_markdown():
    """Verify RunReporter generates valid Markdown."""
    metrics = RunMetrics(
        run_id="test_run",
        started_at=datetime(2024, 1, 15, 12, 0, 0),
        completed_at=datetime(2024, 1, 15, 12, 5, 30)
    )
    metrics.advisories_total = 100
    metrics.state_changes = 15
    metrics.state_counts = {"fixed": 45, "pending_upstream": 55}

    quality_results = [
        QualityCheckResult("check1", True, "Passed"),
        QualityCheckResult("check2", False, "Failed"),
    ]

    reporter = RunReporter()
    report = reporter.generate_report(metrics, quality_results)

    # Verify Markdown structure
    assert "# Pipeline Run Report" in report
    assert "test_run" in report
    assert "Summary" in report
    assert "State Distribution" in report
    assert "Data Quality Checks" in report
    assert "100" in report  # Total advisories
    assert "15" in report  # State changes


def test_reporter_saves_to_file():
    """Verify RunReporter can save reports to file."""
    metrics = RunMetrics(run_id="test_run", started_at=datetime.utcnow())
    quality_results = []

    reporter = RunReporter()
    report = reporter.generate_report(metrics, quality_results)

    with tempfile.TemporaryDirectory() as tmpdir:
        output_dir = Path(tmpdir)
        report_path = reporter.save_report(report, output_dir)

        assert report_path.exists()
        assert report_path.name.startswith("run-report-")
        assert report_path.suffix == ".md"

        # Verify content was written
        content = report_path.read_text()
        assert "Pipeline Run Report" in content


def test_run_metrics_error_tracking():
    """Verify RunMetrics tracks errors correctly."""
    metrics = RunMetrics(run_id="test_run", started_at=datetime.utcnow())

    metrics.record_error("Test error 1")
    metrics.record_error("Test error 2", context={"advisory_id": "test:CVE-2024-0001"})

    assert metrics.errors == 2
    assert len(metrics.quality_issues) == 2
    assert metrics.quality_issues[0]["message"] == "Test error 1"
    assert metrics.quality_issues[1]["context"]["advisory_id"] == "test:CVE-2024-0001"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
