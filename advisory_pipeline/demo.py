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


def show_cve_journey(db: Database, cve_ids: list, run_number: int):
    """
    Display the journey of specific CVEs showing state changes.

    This creates a visual table showing what happened to each tracked CVE.
    """
    conn = db.connect()

    print(f"\n  📊 CVE Journey Tracker - After Run {run_number}")
    print("  " + "=" * 68)

    for cve_id in cve_ids:
        # Get current state
        result = conn.execute("""
            SELECT
                cve_id,
                package_name,
                state,
                fixed_version,
                reason_code,
                explanation,
                confidence
            FROM main_marts.mart_advisory_current
            WHERE cve_id = ?
        """, [cve_id]).fetchone()

        if not result:
            print(f"\n  ❌ {cve_id}: Not found")
            continue

        cve, pkg, state, version, reason, explanation, confidence = result

        # Get state history to show transition
        history = conn.execute("""
            SELECT state, effective_from
            FROM advisory_state_history
            WHERE cve_id = ?
            ORDER BY effective_from
        """, [cve_id]).fetchall()

        # Build state transition string
        if len(history) > 1:
            transition = " → ".join([h[0] for h in history])
        else:
            transition = history[0][0] if history else state

        # Determine icon
        icon = "✅" if state in ["fixed", "not_applicable"] else "⏳"

        print(f"\n  {icon} {cve_id} ({pkg})")
        print(f"     State: {state} (confidence: {confidence})")
        if version:
            print(f"     Fixed in: {version}")
        print(f"     Journey: {transition}")
        print(f"     Why: {explanation[:80]}...")
        print(f"     Rule: {reason}")

    print("  " + "=" * 68)


def run_demo():
    """Execute full demo scenario."""
    # CVEs to track throughout the demo
    tracked_cves = ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004"]

    print("\n" + "=" * 70)
    print("CVE ADVISORY PIPELINE - DEMONSTRATION")
    print("=" * 70)
    print("\nThis demo tracks 4 CVEs through 3 pipeline runs:")
    print("  • CVE-2024-0001: Has fix in OSV from start")
    print("  • CVE-2024-0002: Will be overridden by analyst in Run 2")
    print("  • CVE-2024-0003: Has fix in OSV from start")
    print("  • CVE-2024-0004: No fix initially, gets fix in Run 3")
    print("=" * 70)

    # Setup
    clean_demo_environment()
    setup_mock_data()

    # === RUN 1: Initial Load ===
    print("\n" + "=" * 70)
    print("RUN 1: INITIAL LOAD")
    print("=" * 70)
    print("Input: Echo data.json + NVD + OSV (CVE-0001 and CVE-0003 have fixes)")

    create_csv_override(include_override=False)

    pipeline = AdvisoryPipeline()
    metrics1 = pipeline.run()
    pipeline.db.close()

    db = Database()
    show_cve_journey(db, tracked_cves, 1)
    show_state_distribution(db)
    db.close()

    print(f"\n  ✓ {metrics1.advisories_total} advisories processed")

    # === RUN 2: CSV Override ===
    print("\n" + "=" * 70)
    print("RUN 2: CSV OVERRIDE")
    print("=" * 70)
    print("Input: Analyst adds CSV override for CVE-2024-0002 → not_applicable")

    create_csv_override(include_override=True)

    pipeline2 = AdvisoryPipeline()
    metrics2 = pipeline2.run()
    pipeline2.db.close()

    db = Database()
    show_cve_journey(db, tracked_cves, 2)
    show_state_distribution(db)
    db.close()

    print(f"\n  ✓ {metrics2.state_changes} state change(s) detected")

    # === RUN 3: Upstream Fix ===
    print("\n" + "=" * 70)
    print("RUN 3: UPSTREAM FIX DETECTED")
    print("=" * 70)
    print("Input: OSV now reports fix for CVE-2024-0004 (version 3.0.0)")

    update_osv_with_new_fix()

    pipeline3 = AdvisoryPipeline()
    metrics3 = pipeline3.run()
    pipeline3.db.close()

    db = Database()
    show_cve_journey(db, tracked_cves, 3)
    show_state_distribution(db)
    db.close()

    print(f"\n  ✓ {metrics3.state_changes} state change(s) detected")

    # Summary
    print("\n" + "=" * 70)
    print("DEMO COMPLETE - CVE LIFECYCLE SUMMARY")
    print("=" * 70)
    print("\nFinal States:")
    print("  ✅ CVE-2024-0001: fixed (had upstream fix from start)")
    print("  ✅ CVE-2024-0002: not_applicable (analyst override in Run 2)")
    print("  ✅ CVE-2024-0003: fixed (had upstream fix from start)")
    print("  ✅ CVE-2024-0004: fixed (upstream fix detected in Run 3)")
    print("\nKey Demonstrations:")
    print("  • Rule priority: CSV override (R0) beats upstream fix (R2)")
    print("  • State transitions: Tracked with full SCD Type 2 history")
    print("  • Explainability: Every decision has reason code + explanation")
    print("  • Continuous monitoring: New upstream data triggers updates")
    print("\nOutput files: output/advisory_current.json, output/run_report_*.md")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    try:
        run_demo()
    except Exception as e:
        print(f"\nDemo failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
