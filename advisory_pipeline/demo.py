#!/usr/bin/env python3
"""
Demonstration script for the CVE Advisory Pipeline.

This script runs multiple pipeline iterations to show:
- Initial state establishment
- State transitions based on new data
- CSV override priority
- Upstream fix detection
- SCD Type 2 history tracking

The demo simulates realistic scenarios:
1. Run 1: Initial load with all CVEs in pending/investigation states
2. Run 2: CSV override marks one CVE as not_applicable
3. Run 3: Upstream source (OSV) provides fix, triggering state change

Each run shows:
- What changed in the input data
- How many state transitions occurred
- Current state distribution
- Example state histories for specific CVEs

Usage:
    python demo.py
"""
import sys
import json
import shutil
import csv
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

from run_pipeline import AdvisoryPipeline
from storage.database import Database


def clean_demo_environment():
    """Remove previous demo artifacts for clean run."""
    print("Cleaning previous demo data...")

    # Remove database
    db_path = Path("advisory_pipeline.duckdb")
    if db_path.exists():
        db_path.unlink()
        print("  Removed database")

    # Remove output directory
    output_dir = Path("output")
    if output_dir.exists():
        shutil.rmtree(output_dir)
        print("  Removed output directory")


def setup_mock_data():
    """
    Create mock response files for NVD and OSV.

    This simulates the data that would be fetched from real APIs.
    """
    mock_dir = Path("ingestion/mock_responses")
    mock_dir.mkdir(parents=True, exist_ok=True)

    # NVD mock responses
    nvd_data = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-0001",
                    "vulnStatus": "Analyzed",
                    "descriptions": [
                        {"lang": "en", "value": "Buffer overflow in example package"}
                    ],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 7.5,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                            }
                        }]
                    },
                    "references": [{"url": "https://example.com/advisory/1"}]
                }
            },
            {
                "cve": {
                    "id": "CVE-2024-0002",
                    "vulnStatus": "Analyzed",
                    "descriptions": [
                        {"lang": "en", "value": "Information disclosure"}
                    ],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 5.0,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
                            }
                        }]
                    },
                    "references": []
                }
            },
            {
                "cve": {
                    "id": "CVE-2024-0003",
                    "vulnStatus": "Analyzed",
                    "descriptions": [
                        {"lang": "en", "value": "SQL injection vulnerability"}
                    ],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 9.8,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                            }
                        }]
                    },
                    "references": [{"url": "https://example.com/advisory/3"}]
                }
            }
        ]
    }

    with open(mock_dir / "nvd_responses.json", "w") as f:
        json.dump(nvd_data, f, indent=2)

    # Initial OSV responses (Run 1 & 2)
    osv_data_initial = {
        "vulns": [
            {
                "id": "GHSA-0001-0001-0001",
                "aliases": ["CVE-2024-0001"],
                "summary": "Buffer overflow allows remote code execution",
                "affected": [{
                    "package": {"name": "example-package", "ecosystem": "PyPI"},
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]
                    }]
                }],
                "references": [
                    {"type": "FIX", "url": "https://github.com/example/commit/abc123"}
                ]
            },
            {
                "id": "GHSA-0002-0002-0002",
                "aliases": ["CVE-2024-0003"],
                "summary": "SQL injection in database handler",
                "affected": [{
                    "package": {"name": "db-handler", "ecosystem": "npm"},
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]
                    }]
                }],
                "references": [
                    {"type": "FIX", "url": "https://github.com/example/commit/def456"}
                ]
            },
            {
                "id": "GHSA-0003-0003-0003",
                "aliases": ["CVE-2024-0004"],
                "summary": "Denial of service via crafted input",
                "affected": [{
                    "package": {"name": "parser-lib", "ecosystem": "PyPI"},
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}]  # No fix yet
                    }]
                }],
                "references": []
            }
        ]
    }

    with open(mock_dir / "osv_responses.json", "w") as f:
        json.dump(osv_data_initial, f, indent=2)

    print("Created mock API response files")


def create_csv_override(include_override: bool = False):
    """
    Create CSV override file.

    Args:
        include_override: If True, adds CVE-2024-0002 as not_applicable
    """
    csv_path = Path("data/echo_overrides.csv")

    if not include_override:
        # No overrides for Run 1
        if csv_path.exists():
            csv_path.unlink()
        return

    # Create override for Run 2
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "package_name", "cve_id", "status", "reason", "analyst", "updated_at"
        ])
        writer.writeheader()
        writer.writerow({
            "package_name": "example-package",
            "cve_id": "CVE-2024-0002",
            "status": "not_applicable",
            "reason": "Vulnerable code path not used in our configuration",
            "analyst": "security-team",
            "updated_at": datetime.utcnow().isoformat()
        })


def update_osv_with_new_fix():
    """
    Update OSV mock to include fix for CVE-2024-0004.

    This simulates upstream providing a fix in Run 3.
    """
    mock_dir = Path("ingestion/mock_responses")

    osv_data_with_fix = {
        "vulns": [
            {
                "id": "GHSA-0001-0001-0001",
                "aliases": ["CVE-2024-0001"],
                "summary": "Buffer overflow allows remote code execution",
                "affected": [{
                    "package": {"name": "example-package", "ecosystem": "PyPI"},
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]
                    }]
                }],
                "references": [
                    {"type": "FIX", "url": "https://github.com/example/commit/abc123"}
                ]
            },
            {
                "id": "GHSA-0002-0002-0002",
                "aliases": ["CVE-2024-0003"],
                "summary": "SQL injection in database handler",
                "affected": [{
                    "package": {"name": "db-handler", "ecosystem": "npm"},
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]
                    }]
                }],
                "references": [
                    {"type": "FIX", "url": "https://github.com/example/commit/def456"}
                ]
            },
            {
                "id": "GHSA-0003-0003-0003",
                "aliases": ["CVE-2024-0004"],
                "summary": "Denial of service via crafted input",
                "affected": [{
                    "package": {"name": "parser-lib", "ecosystem": "PyPI"},
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "3.0.0"}]  # NOW FIXED!
                    }]
                }],
                "references": [
                    {"type": "FIX", "url": "https://github.com/parser/commit/ghi789"}
                ]
            }
        ]
    }

    with open(mock_dir / "osv_responses.json", "w") as f:
        json.dump(osv_data_with_fix, f, indent=2)


def show_state_distribution(db: Database):
    """Display current state distribution."""
    conn = db.connect()
    results = conn.execute("""
        SELECT state, count(*) as count
        FROM main_marts.mart_advisory_current
        GROUP BY state
        ORDER BY count DESC
    """).fetchall()

    print("\n  Current State Distribution:")
    for state, count in results:
        print(f"    {state:25} {count:3}")


def show_cve_history(db: Database, cve_id: str):
    """Display state history for a specific CVE."""
    conn = db.connect()
    results = conn.execute("""
        SELECT
            state,
            reason_code,
            decided_at,
            run_id
        FROM main_marts.mart_advisory_current
        WHERE cve_id = ?
    """, [cve_id]).fetchall()

    if not results:
        print(f"\n  No history found for {cve_id}")
        return

    print(f"\n  Current State for {cve_id}:")
    for state, reason_code, decided_at, run_id in results:
        timestamp = decided_at.isoformat()[:19] if decided_at else "unknown"
        print(f"    {state:20} | {reason_code:20} | {run_id}")


def run_demo():
    """Execute full demo scenario."""
    print("\n" + "=" * 70)
    print("CVE ADVISORY PIPELINE - DEMONSTRATION")
    print("=" * 70)
    print("\nThis demo shows:")
    print("  1. Initial pipeline run with base data")
    print("  2. CSV override changing state (not_applicable)")
    print("  3. Upstream fix detection triggering state change")
    print("=" * 70)

    # Setup
    clean_demo_environment()
    setup_mock_data()

    # === RUN 1: Initial Load ===
    print("\n" + "=" * 70)
    print("RUN 1: INITIAL LOAD")
    print("=" * 70)
    print("Scenario: Fresh database, no overrides")

    create_csv_override(include_override=False)

    pipeline = AdvisoryPipeline()
    metrics1 = pipeline.run()
    pipeline.db.close()  # Close DB connection after run

    db = Database()
    show_state_distribution(db)
    show_cve_history(db, "CVE-2024-0001")
    db.close()

    print(f"\nResult: {metrics1.advisories_total} advisories processed")

    # === RUN 2: CSV Override ===
    print("\n" + "=" * 70)
    print("RUN 2: CSV OVERRIDE")
    print("=" * 70)
    print("Scenario: Security team marks CVE-2024-0002 as not_applicable")

    create_csv_override(include_override=True)

    pipeline2 = AdvisoryPipeline()
    metrics2 = pipeline2.run()
    pipeline2.db.close()  # Close DB connection after run

    db = Database()
    show_state_distribution(db)
    show_cve_history(db, "CVE-2024-0002")
    db.close()

    print(f"\nResult: {metrics2.state_changes} state change(s)")

    # === RUN 3: Upstream Fix ===
    print("\n" + "=" * 70)
    print("RUN 3: UPSTREAM FIX DETECTED")
    print("=" * 70)
    print("Scenario: OSV now shows fix for CVE-2024-0004")

    update_osv_with_new_fix()

    pipeline3 = AdvisoryPipeline()
    metrics3 = pipeline3.run()
    pipeline3.db.close()  # Close DB connection after run

    db = Database()
    show_state_distribution(db)
    show_cve_history(db, "CVE-2024-0004")
    db.close()

    print(f"\nResult: {metrics3.state_changes} state change(s)")

    # Summary
    print("\n" + "=" * 70)
    print("DEMO COMPLETE")
    print("=" * 70)
    print(f"\nTotal Runs: 3")
    print(f"Final Advisory Count: {metrics3.advisories_total}")
    print(f"\nOutput files generated:")
    print(f"  - output/advisory_current.json")
    print(f"  - output/run_report_*.md (3 reports)")
    print("\nTo explore:")
    print(f"  - Check advisory_pipeline.duckdb for full state history")
    print(f"  - Review output/advisory_current.json for current state")
    print(f"  - Read output/run_report_*.md for detailed metrics")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    try:
        run_demo()
    except Exception as e:
        print(f"\nDemo failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
