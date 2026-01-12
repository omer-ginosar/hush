#!/usr/bin/env python3
"""
Main pipeline orchestrator for the CVE Advisory Pipeline.

This module coordinates the entire advisory enrichment process:
1. Ingestion: Fetch observations from all configured sources
2. Loading: Store raw observations in DuckDB landing zone
3. Transformation: Execute dbt models to enrich and decide
4. State Management: Apply SCD Type 2 state changes
5. Quality: Run data quality checks
6. Reporting: Generate run reports and export outputs

The orchestrator is designed to be:
- Idempotent: Safe to re-run with the same run_id
- Observable: Comprehensive metrics and logging
- Deterministic: Same inputs always produce same outputs
- Composable: Each stage can be independently tested

Usage:
    python run_pipeline.py [--config path/to/config.yaml]
"""
import os
import sys
import json
import yaml
import logging
import argparse
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

from storage.database import Database
from storage.loader import SourceLoader
from ingestion.echo_data_adapter import EchoDataAdapter
from ingestion.echo_csv_adapter import EchoCsvAdapter
from ingestion.nvd_adapter import NvdAdapter
from ingestion.osv_adapter import OsvAdapter
from ingestion.base_adapter import SourceObservation
from observability.metrics import RunMetrics
from observability.quality_checks import QualityChecker
from observability.reporter import RunReporter

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AdvisoryPipeline:
    """
    Main pipeline orchestrator that coordinates all stages.

    The pipeline follows a strict execution order:
    1. Initialize database schema
    2. Ingest from all sources (adapters)
    3. Load observations into raw tables
    4. Execute dbt transformations (staging → intermediate → marts)
    5. Export current state to JSON
    6. Run quality checks
    7. Generate reports

    Design decisions:
    - Single run_id tracks entire execution
    - dbt handles all SQL transformations
    - Python handles orchestration and I/O
    - Metrics captured at every stage
    - Failures are logged but don't halt quality checks
    """

    def __init__(self, config_path: str = "config.yaml"):
        """
        Initialize pipeline with configuration.

        Args:
            config_path: Path to YAML configuration file
        """
        self.config_path = Path(config_path)
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        with open(self.config_path) as f:
            self.config = yaml.safe_load(f)

        # Initialize core components
        self.db = Database(self.config["database"]["path"])
        self.loader = SourceLoader(self.db)
        self.quality_checker = QualityChecker(self.db)
        self.reporter = RunReporter()

        # Validate required configuration keys
        required_keys = ["database", "sources"]
        for key in required_keys:
            if key not in self.config:
                raise ValueError(f"Missing required config key: {key}")

        required_sources = ["echo_data", "echo_csv", "nvd", "osv"]
        if "sources" not in self.config:
            raise ValueError("Missing 'sources' section in config")

        for source in required_sources:
            if source not in self.config["sources"]:
                raise ValueError(f"Missing required source configuration: sources.{source}")

        # Initialize source adapters
        self.adapters = {
            "echo_data": EchoDataAdapter(self.config["sources"]["echo_data"]),
            "echo_csv": EchoCsvAdapter(self.config["sources"]["echo_csv"]),
            "nvd": NvdAdapter(self.config["sources"]["nvd"]),
            "osv": OsvAdapter(self.config["sources"]["osv"]),
        }

        logger.info(f"Pipeline initialized with config: {config_path}")

    def run(self) -> RunMetrics:
        """
        Execute complete pipeline run.

        Returns:
            RunMetrics object with execution statistics

        Raises:
            RuntimeError: If critical stage fails
        """
        run_id = self.db.get_current_run_id()
        metrics = RunMetrics(run_id=run_id, started_at=datetime.utcnow())

        logger.info(f"=== Starting Pipeline Run: {run_id} ===")

        try:
            # Stage 1: Database initialization
            logger.info("Stage 1: Initializing database schema")
            self.db.initialize_schema()

            # Stage 2: Ingestion
            logger.info("Stage 2: Ingesting from all sources")
            self._ingest_all_sources(run_id, metrics)

            # Stage 3: dbt transformations
            logger.info("Stage 3: Running dbt transformations")
            self._run_dbt_models(run_id)

            # Stage 3b: dbt snapshots (SCD2 state tracking)
            logger.info("Stage 3b: Running dbt snapshots")
            self._run_dbt_snapshots(run_id)

            # Stage 4: Export outputs
            logger.info("Stage 4: Exporting advisory state")
            self._export_current_state()

            # Stage 5: Quality checks
            logger.info("Stage 5: Running quality checks")
            quality_results = self.quality_checker.run_all_checks()

            # Stage 6: Finalize metrics and reporting
            logger.info("Stage 6: Generating reports")
            self._finalize_metrics(metrics)
            report = self.reporter.generate_report(metrics, quality_results)
            report_path = self.reporter.save_report(report, Path("output"))

            metrics.completed_at = datetime.utcnow()
            duration = (metrics.completed_at - metrics.started_at).total_seconds()

            logger.info(f"=== Pipeline Complete ===")
            logger.info(f"Duration: {duration:.1f}s")
            logger.info(f"Advisories: {metrics.advisories_total}")
            logger.info(f"State changes: {metrics.state_changes}")
            logger.info(f"Report: {report_path}")

        except Exception as e:
            metrics.record_error(str(e))
            logger.error(f"Pipeline failed: {e}", exc_info=True)
            raise RuntimeError(f"Pipeline execution failed: {e}") from e

        return metrics

    def _ingest_all_sources(self, run_id: str, metrics: RunMetrics):
        """
        Ingest observations from all configured sources.

        For each source:
        1. Fetch observations using adapter
        2. Load into appropriate raw table
        3. Record source health metrics

        Args:
            run_id: Pipeline run identifier
            metrics: RunMetrics to update
        """
        for source_name, adapter in self.adapters.items():
            try:
                logger.info(f"  Fetching from {source_name}")
                observations = adapter.fetch()

                # Load to appropriate raw table
                loaded_count = self._load_observations(
                    source_name, observations, run_id
                )

                # Record source health
                health = adapter.get_health()
                metrics.source_health[source_name] = {
                    "healthy": health.is_healthy,
                    "records": loaded_count,
                    "error": health.error_message
                }

                logger.info(f"    Loaded {loaded_count} observations")

            except Exception as e:
                logger.error(f"  Error ingesting from {source_name}: {e}")
                metrics.record_error(f"Ingestion failed for {source_name}: {e}")
                metrics.source_health[source_name] = {
                    "healthy": False,
                    "records": 0,
                    "error": str(e)
                }

    def _load_observations(
        self,
        source_name: str,
        observations: List[SourceObservation],
        run_id: str
    ) -> int:
        """
        Load observations to appropriate raw table based on source.

        Args:
            source_name: Source identifier (echo_data, echo_csv, nvd, osv)
            observations: List of normalized observations
            run_id: Pipeline run identifier

        Returns:
            Number of records loaded
        """
        if source_name == "echo_data":
            return self.loader.load_echo_advisories(observations, run_id)
        elif source_name == "echo_csv":
            return self.loader.load_echo_csv(observations, run_id)
        elif source_name == "nvd":
            return self.loader.load_nvd_observations(observations, run_id)
        elif source_name == "osv":
            return self.loader.load_osv_observations(observations, run_id)
        else:
            logger.warning(f"Unknown source: {source_name}")
            return 0

    def _run_dbt_models(self, run_id: str):
        """
        Execute dbt models to transform raw data into marts.

        The dbt run executes in order:
        1. staging: Clean and normalize raw observations
        2. intermediate: Enrich and aggregate signals
        3. marts: Apply decision rules and generate current state

        Args:
            run_id: Pipeline run identifier (passed to dbt as env var)

        Raises:
            RuntimeError: If dbt execution fails
        """
        # Use absolute path to dbt project directory
        script_dir = Path(__file__).parent
        dbt_dir = script_dir / "dbt_project"
        if not dbt_dir.exists():
            raise RuntimeError(f"dbt project directory not found: {dbt_dir}")

        # Close database connection before dbt runs
        # This prevents DuckDB locking issues
        self.db.close()

        # Set run ID as environment variable for dbt
        env = os.environ.copy()
        env["PIPELINE_RUN_ID"] = run_id

        # Execute dbt run
        result = subprocess.run(
            ["dbt", "run", "--profiles-dir", "."],
            cwd=dbt_dir,
            env=env,
            capture_output=True,
            text=True
        )

        # Reconnect database after dbt completes
        self.db.connect()

        if result.returncode != 0:
            logger.error(f"dbt stdout:\n{result.stdout}")
            logger.error(f"dbt stderr:\n{result.stderr}")
            raise RuntimeError(f"dbt run failed with code {result.returncode}")

        logger.info("  dbt models completed successfully")

    def _run_dbt_snapshots(self, run_id: str):
        """
        Execute dbt snapshots to track state changes over time.

        dbt snapshots implement SCD Type 2 pattern, automatically detecting
        changes in mart_advisory_current and creating history records.

        Args:
            run_id: Pipeline run identifier (passed to dbt as env var)

        Raises:
            RuntimeError: If dbt snapshot execution fails
        """
        script_dir = Path(__file__).parent
        dbt_dir = script_dir / "dbt_project"

        # Close database connection before dbt runs
        self.db.close()

        # Set run ID as environment variable for dbt
        env = os.environ.copy()
        env["PIPELINE_RUN_ID"] = run_id

        # Execute dbt snapshot
        result = subprocess.run(
            ["dbt", "snapshot", "--profiles-dir", "."],
            cwd=dbt_dir,
            env=env,
            capture_output=True,
            text=True
        )

        # Reconnect database after dbt completes
        self.db.connect()

        if result.returncode != 0:
            logger.error(f"dbt snapshot stdout:\n{result.stdout}")
            logger.error(f"dbt snapshot stderr:\n{result.stderr}")
            raise RuntimeError(f"dbt snapshot failed with code {result.returncode}")

        logger.info("  dbt snapshots completed successfully")

    def _export_current_state(self):
        """
        Export current advisory state to JSON file.

        Reads from mart_advisory_current (dbt output) and writes to
        output/advisory_current.json for downstream consumers.

        Output format:
        {
          "generated_at": "2024-01-11T12:00:00Z",
          "advisory_count": 42,
          "advisories": [...]
        }
        """
        conn = self.db.connect()

        # Check if mart table exists before querying
        table_check = conn.execute("""
            SELECT count(*)
            FROM information_schema.tables
            WHERE table_schema = 'main_marts'
              AND table_name = 'mart_advisory_current'
        """).fetchone()

        if not table_check or table_check[0] == 0:
            logger.warning("mart_advisory_current table not found - dbt may not have run successfully")
            return {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "advisory_count": 0,
                "advisories": [],
                "warning": "dbt mart table not found"
            }

        # Query current state from dbt mart
        try:
            results = conn.execute("""
                SELECT
                    advisory_id,
                    cve_id,
                    package_name,
                    state,
                    state_type,
                    fixed_version,
                    confidence,
                    explanation,
                    reason_code,
                    contributing_sources,
                    dissenting_sources,
                    decided_at,
                    run_id
                FROM main_marts.mart_advisory_current
            """).fetchall()
        except Exception as e:
            logger.error(f"Failed to query mart_advisory_current: {e}")
            raise RuntimeError(f"Database query failed: {e}") from e

        # Convert to list of dictionaries
        columns = [desc[0] for desc in conn.description]
        advisories = []

        for row in results:
            adv = dict(zip(columns, row))

            # Convert timestamp to ISO string
            if adv.get("decided_at"):
                adv["decided_at"] = adv["decided_at"].isoformat()

            # Parse JSON fields if they're strings
            for json_field in ["contributing_sources", "dissenting_sources"]:
                if adv.get(json_field) and isinstance(adv[json_field], str):
                    try:
                        adv[json_field] = json.loads(adv[json_field])
                    except json.JSONDecodeError as e:
                        logger.warning(
                            f"Failed to parse {json_field} for advisory {adv.get('advisory_id')}: {e}. "
                            f"Raw value: {adv[json_field][:100]}"
                        )
                        adv[json_field] = []

            advisories.append(adv)

        # Build output document
        output = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "advisory_count": len(advisories),
            "advisories": advisories
        }

        # Write to file
        output_path = Path("output/advisory_current.json")
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(output, f, indent=2)

        logger.info(f"  Exported {len(advisories)} advisories to {output_path}")

    def _finalize_metrics(self, metrics: RunMetrics):
        """
        Calculate final metrics from database state.

        Queries:
        - State distribution (count by state)
        - Total advisories processed
        - State changes (from dbt snapshot history)

        Args:
            metrics: RunMetrics to update
        """
        conn = self.db.connect()

        # Get state distribution
        state_results = conn.execute("""
            SELECT state, count(*)
            FROM main_marts.mart_advisory_current
            GROUP BY state
        """).fetchall()

        metrics.state_counts = {row[0]: row[1] for row in state_results}

        # Get total count
        total = conn.execute("""
            SELECT count(*) FROM main_marts.mart_advisory_current
        """).fetchone()[0]

        metrics.advisories_total = total
        metrics.advisories_processed = total

        # Count state changes in this run from snapshot history
        # State changes are records where dbt_updated_at matches current run
        # and there exists a previous record (dbt_valid_from < current run time)
        try:
            snapshot_exists = conn.execute("""
                SELECT count(*)
                FROM information_schema.tables
                WHERE table_schema = 'main'
                  AND table_name = 'advisory_state_snapshot'
            """).fetchone()[0]

            if snapshot_exists > 0:
                # Count transitions: records that have both a previous and current version
                state_changes = conn.execute("""
                    WITH current_run_records AS (
                        SELECT advisory_id
                        FROM main.advisory_state_snapshot
                        WHERE dbt_valid_from >= (
                            SELECT max(started_at)
                            FROM pipeline_runs
                            WHERE run_id = ?
                        )
                    ),
                    has_history AS (
                        SELECT DISTINCT curr.advisory_id
                        FROM current_run_records curr
                        WHERE EXISTS (
                            SELECT 1
                            FROM main.advisory_state_snapshot prev
                            WHERE prev.advisory_id = curr.advisory_id
                              AND prev.dbt_valid_to IS NOT NULL
                        )
                    )
                    SELECT count(*) FROM has_history
                """, [metrics.run_id]).fetchone()[0]

                metrics.state_changes = state_changes

        except Exception as e:
            logger.warning(f"Could not calculate state changes from snapshot: {e}")
            metrics.state_changes = 0


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Run the CVE Advisory Pipeline"
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to configuration file (default: config.yaml)"
    )
    args = parser.parse_args()

    try:
        pipeline = AdvisoryPipeline(config_path=args.config)
        metrics = pipeline.run()

        # Print summary
        print("\n" + "=" * 60)
        print("Pipeline Summary")
        print("=" * 60)
        print(f"Run ID: {metrics.run_id}")
        print(f"Advisories: {metrics.advisories_total}")
        print(f"State Changes: {metrics.state_changes}")
        print(f"Errors: {metrics.errors}")
        print("\nState Distribution:")
        for state, count in sorted(metrics.state_counts.items()):
            print(f"  {state:20} {count:4}")
        print("=" * 60)

        sys.exit(0)

    except Exception as e:
        logger.error(f"Pipeline failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
