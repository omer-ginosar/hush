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
import yaml
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

    Demo tracks 4 REAL CVEs from Echo's data.json:
    - CVE-2020-10735 (python3.11): Already has fix in Echo data
    - CVE-2008-4677 (vim): No fix initially, analyst overrides in Run 2
    - CVE-2023-37920 (python-certifi): Already has fix, stays fixed
    - CVE-2025-14017 (curl): No fix initially, gets upstream fix in Run 3
    """
    mock_dir = Path("ingestion/mock_responses")
    mock_dir.mkdir(parents=True, exist_ok=True)

    # NVD mock responses for real CVEs
    nvd_data = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2020-10735",
                    "vulnStatus": "Analyzed",
                    "descriptions": [
                        {"lang": "en", "value": "Integer overflow in Python string-to-integer conversion"}
                    ],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 7.5,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                            }
                        }]
                    },
                    "references": [{"url": "https://python.org/advisory/CVE-2020-10735"}]
                }
            },
            {
                "cve": {
                    "id": "CVE-2023-37920",
                    "vulnStatus": "Analyzed",
                    "descriptions": [
                        {"lang": "en", "value": "Certifi certificate trust store issue"}
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
                    "id": "CVE-2008-4677",
                    "vulnStatus": "Analyzed",
                    "descriptions": [
                        {"lang": "en", "value": "Vim arbitrary command execution"}
                    ],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 9.8,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                            }
                        }]
                    },
                    "references": [{"url": "https://www.vim.org/security/"}]
                }
            }
        ]
    }

    with open(mock_dir / "nvd_responses.json", "w") as f:
        json.dump(nvd_data, f, indent=2)

    # Initial OSV responses (Run 1 & 2) - using real CVEs
    osv_data_initial = {
        "vulns": [
            {
                "id": "GHSA-p2g7-xwvr-rrw3",
                "aliases": ["CVE-2020-10735"],
                "summary": "Integer overflow in Python string-to-integer conversion",
                "affected": [{
                    "package": {"name": "python3.11", "ecosystem": "Debian"},
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "3.11.0~rc2-1"}]
                    }]
                }],
                "references": [
                    {"type": "FIX", "url": "https://github.com/python/cpython/issues/95778"}
                ]
            },
            {
                "id": "GHSA-xqr8-7jwr-rhp7",
                "aliases": ["CVE-2023-37920"],
                "summary": "Certifi certificate trust store issue",
                "affected": [{
                    "package": {"name": "python-certifi", "ecosystem": "Debian"},
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2022.9.24-1"}]
                    }]
                }],
                "references": []
            },
            {
                "id": "GHSA-vim-2008-4677",
                "aliases": ["CVE-2008-4677"],
                "summary": "Vim arbitrary command execution vulnerability",
                "affected": [{
                    "package": {"name": "vim", "ecosystem": "Debian"},
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}]  # No fix in Echo data
                    }]
                }],
                "references": []
            },
            {
                "id": "GHSA-curl-2025-14017",
                "aliases": ["CVE-2025-14017"],
                "summary": "Curl security vulnerability",
                "affected": [{
                    "package": {"name": "curl", "ecosystem": "Debian"},
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}]  # No fix yet (will add in Run 3)
                    }]
                }],
                "references": []
            }
        ]
    }

    with open(mock_dir / "osv_responses.json", "w") as f:
        json.dump(osv_data_initial, f, indent=2)

    print("Created mock API response files")


def build_demo_config() -> Path:
    """Create a demo-specific config that forces mock adapters."""
    config_path = Path("config.yaml")
    if not config_path.exists():
        raise FileNotFoundError("config.yaml not found for demo")

    with open(config_path, "r") as handle:
        config = yaml.safe_load(handle)

    config.setdefault("sources", {})
    config["sources"].setdefault("nvd", {})
    config["sources"].setdefault("osv", {})
    config["sources"]["nvd"]["use_mock"] = True
    config["sources"]["osv"]["use_mock"] = True

    output_dir = Path("output")
    output_dir.mkdir(parents=True, exist_ok=True)
    demo_config_path = output_dir / "demo_config.yaml"

    with open(demo_config_path, "w") as handle:
        yaml.safe_dump(config, handle, sort_keys=False)

    return demo_config_path


def create_csv_override(include_override: bool = False):
    """
    Manage CSV override file for demo.

    Args:
        include_override: If True, adds CVE-2008-4677 as not_applicable (Run 2+)
                         If False, uses CSV as-is (Run 1)

    Demo flow:
    - Run 1: CVE-2008-4677 NOT in CSV → shows as pending_upstream
    - Run 2: CVE-2008-4677 ADDED to CSV → shows as not_applicable (analyst override)
    - Run 3: CVE-2008-4677 stays in CSV → remains not_applicable
    """
    csv_path = Path("../advisory_not_applicable.csv")

    # Read existing CSV (don't modify it)
    existing_overrides = []
    if csv_path.exists():
        with open(csv_path, "r", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                existing_overrides.append(row)

    # Write back with optional demo CVE
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "cve_id", "package", "status", "fixed_version", "internal_status"
        ])
        writer.writeheader()

        # Write all existing overrides
        for row in existing_overrides:
            writer.writerow(row)

        # Add demo override in Run 2+ (when include_override=True)
        if include_override:
            writer.writerow({
                "cve_id": "CVE-2008-4677",
                "package": "vim",
                "status": "not_applicable",
                "fixed_version": "",
                "internal_status": "Internal classification - not exploitable in our environment"
            })


def update_osv_with_new_fix():
    """
    Update OSV mock to include fix for CVE-2025-14017.

    DEMO SIMULATION: This simulates upstream providing a fix in Run 3.
    In production, this would come from a fresh OSV data dump fetch.
    """
    mock_dir = Path("ingestion/mock_responses")

    osv_data_with_fix = {
        "vulns": [
            {
                "id": "GHSA-p2g7-xwvr-rrw3",
                "aliases": ["CVE-2020-10735"],
                "summary": "Integer overflow in Python string-to-integer conversion",
                "affected": [{
                    "package": {"name": "python3.11", "ecosystem": "Debian"},
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "3.11.0~rc2-1"}]
                    }]
                }],
                "references": [
                    {"type": "FIX", "url": "https://github.com/python/cpython/issues/95778"}
                ]
            },
            {
                "id": "GHSA-vim-2008-4677",
                "aliases": ["CVE-2008-4677"],
                "summary": "Vim arbitrary command execution vulnerability",
                "affected": [{
                    "package": {"name": "vim", "ecosystem": "Debian"},
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}]  # Still no fix
                    }]
                }],
                "references": []
            },
            {
                "id": "GHSA-curl-2025-14017",
                "aliases": ["CVE-2025-14017"],
                "summary": "Curl security vulnerability",
                "affected": [{
                    "package": {"name": "curl", "ecosystem": "Debian"},
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "8.12.0-1"}]  # NOW FIXED!
                    }]
                }],
                "references": [
                    {"type": "FIX", "url": "https://github.com/curl/curl/commit/simulated-fix"}
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
        # Get ALL entries for this CVE (may have multiple due to different packages/sources)
        results = conn.execute("""
            SELECT
                cve_id,
                package_name,
                state,
                fixed_version,
                reason_code,
                explanation,
                confidence,
                decision_rule
            FROM main_marts.mart_advisory_current
            WHERE cve_id = ?
            ORDER BY CASE WHEN package_name IS NOT NULL THEN 0 ELSE 1 END, package_name
        """, [cve_id]).fetchall()

        if not results:
            print(f"\n  ❌ {cve_id}: Not found")
            continue

        # Show primary entry (with package if available)
        for idx, result in enumerate(results):
            cve, pkg, state, version, reason, explanation, confidence, rule = result

            # Determine icon
            icon = "✅" if state in ["fixed", "not_applicable"] else "⏳"

            pkg_display = pkg if pkg else "NULL"
            prefix = "  " if idx == 0 else "     ↳"

            print(f"\n  {prefix} {icon} {cve_id} ({pkg_display})")
            print(f"       State: {state} (confidence: {confidence})")
            if version:
                print(f"       Fixed in: {version}")
            print(f"       Why: {explanation[:72]}...")
            print(f"       Rule: {rule}")

    print("  " + "=" * 68)


def show_scd2_table(db: Database, cve_ids: list, run_number: int):
    """Display SCD2 history table for tracked CVEs."""
    conn = db.connect()

    print(f"\n  📋 SCD2 History Table - After Run {run_number}")
    print("  " + "=" * 68)

    for cve_id in cve_ids:
        history = conn.execute("""
            SELECT
                cve_id,
                package_name,
                state,
                effective_from,
                effective_to,
                is_current,
                run_id
            FROM main_marts.advisory_state_history
            WHERE cve_id = ?
            ORDER BY effective_from
        """, [cve_id]).fetchall()

        if not history:
            # Check if CVE exists in mart (SCD2 might not be populated)
            exists = conn.execute("""
                SELECT COUNT(*) FROM main_marts.mart_advisory_current
                WHERE cve_id = ?
            """, [cve_id]).fetchone()[0]

            if exists > 0:
                print(f"\n  ⚠️  {cve_id}: No SCD2 history (pipeline doesn't populate it)")
            else:
                print(f"\n  ❌ {cve_id}: Not found")
            continue

        print(f"\n  {cve_id}:")
        print(f"     {'Package':<18} {'State':<18} {'From':<20} {'To':<20} {'Cur'} {'Run ID'}")
        print("     " + "-" * 100)

        for row in history:
            cve, pkg, state, from_dt, to_dt, is_current, run_id = row
            pkg_display = (pkg if pkg else "NULL")[:16]
            from_str = str(from_dt)[:19] if from_dt else "N/A"
            to_str = str(to_dt)[:19] if to_dt else "NULL"
            current_mark = "✓" if is_current else ""

            print(f"     {pkg_display:<18} {state:<18} {from_str:<20} {to_str:<20} {current_mark:<3} {run_id}")

    print("  " + "=" * 68)


def run_demo():
    """Execute full demo scenario."""
    # REAL CVEs to track throughout the demo (from Echo's data.json)
    tracked_cves = ["CVE-2020-10735", "CVE-2023-37920", "CVE-2008-4677", "CVE-2025-14017"]

    print("\n" + "=" * 70)
    print("CVE ADVISORY PIPELINE - DEMONSTRATION")
    print("=" * 70)
    print("\nThis demo tracks 4 REAL CVEs through 3 pipeline runs:")
    print("  • CVE-2020-10735 (python3.11): Has fix from start")
    print("  • CVE-2008-4677 (vim): No fix, analyst overrides in Run 2")
    print("  • CVE-2023-37920 (python-certifi): Has fix, stays fixed")
    print("  • CVE-2025-14017 (curl): No fix initially, gets upstream fix in Run 3")
    print("=" * 70)

    # Setup
    clean_demo_environment()
    setup_mock_data()
    demo_config = build_demo_config()

    # === RUN 1: Initial Load ===
    print("\n" + "=" * 70)
    print("RUN 1: INITIAL LOAD")
    print("=" * 70)
    print("Input: Echo data.json + NVD + OSV")
    print("       CVE-2020-10735 & CVE-2023-37920 have fixes from upstream")
    print("       CVE-2008-4677 & CVE-2025-14017 have no fix yet")

    create_csv_override(include_override=False)

    pipeline = AdvisoryPipeline(str(demo_config))
    metrics1 = pipeline.run()
    pipeline.db.close()

    db = Database()
    show_cve_journey(db, tracked_cves, 1)
    show_scd2_table(db, tracked_cves, 1)
    show_state_distribution(db)
    db.close()

    print(f"\n  ✓ {metrics1.advisories_total} advisories processed")

    # === RUN 2: CSV Override ===
    print("\n" + "=" * 70)
    print("RUN 2: ANALYST OVERRIDE")
    print("=" * 70)
    print("Input: Analyst adds CVE-2008-4677 (vim) to CSV → not_applicable")
    print("       (Shows CSV override changes state from pending_upstream)")

    create_csv_override(include_override=True)

    pipeline2 = AdvisoryPipeline(str(demo_config))
    metrics2 = pipeline2.run()
    pipeline2.db.close()

    db = Database()
    show_cve_journey(db, tracked_cves, 2)
    show_scd2_table(db, tracked_cves, 2)
    show_state_distribution(db)
    db.close()

    print(f"\n  ✓ {metrics2.state_changes} state change(s) detected")

    # === RUN 3: Upstream Fix ===
    print("\n" + "=" * 70)
    print("RUN 3: UPSTREAM FIX DETECTED (SIMULATED)")
    print("=" * 70)
    print("Input: OSV now reports fix for CVE-2025-14017 (version 8.12.0-1)")
    print("       NOTE: Simulated for demo - in production this comes from OSV dump")

    update_osv_with_new_fix()

    pipeline3 = AdvisoryPipeline(str(demo_config))
    metrics3 = pipeline3.run()
    pipeline3.db.close()

    db = Database()
    show_cve_journey(db, tracked_cves, 3)
    show_scd2_table(db, tracked_cves, 3)
    show_state_distribution(db)
    db.close()

    print(f"\n  ✓ {metrics3.state_changes} state change(s) detected")

    # Summary
    print("\n" + "=" * 70)
    print("DEMO COMPLETE")
    print("=" * 70)
    print(f"\nTotal advisories processed: {metrics3.advisories_total}")
    print(f"Output files: output/advisory_current.json, output/run_report_*.md")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    try:
        run_demo()
    except Exception as e:
        print(f"\nDemo failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
