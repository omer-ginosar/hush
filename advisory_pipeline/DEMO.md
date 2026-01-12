# Advisory Pipeline Demo: Visual CVE Journey Tracking

## Overview

This demo showcases the Advisory Pipeline's end-to-end CVE lifecycle management across three pipeline runs. It demonstrates state transitions, CSV overrides, upstream fix detection, SCD2 history tracking, and the **granularity architecture fix** with visual, easy-to-understand output.

## What the Demo Shows

1. **Visual CVE Journey Tracking** - Current state for each tracked CVE with icons (✅ ⏳)
2. **SCD2 State History** - Historical state transitions with timestamps and run IDs
3. **CSV Override Priority** - Analyst decisions override upstream sources
4. **Upstream Fix Detection** - Automatic state changes when fixes are published
5. **Package-Level Granularity** - Single granularity with NVD data denormalized
6. **Rule-Based Decisions** - Clear explanations of why each decision was made
7. **Large-Scale Processing** - Handles ~40k real CVEs from Echo's data.json

## Running the Demo

```bash
cd advisory_pipeline
export PATH="/Users/omerginosar/Library/Python/3.9/bin:$PATH"  # Ensure dbt is in PATH
python3 demo.py
```

The demo runs 3 complete pipeline iterations (~3-4 minutes total):
- **Run 1**: Initial load - establishes baseline states
- **Run 2**: CSV override - analyst marks CVE-2024-0003 as not_applicable (overrides OSV fix)
- **Run 3**: Upstream fix - OSV reports fix for CVE-2024-0004

## What You'll See

### CVE Journey Tracker

Shows current state after each run with visual indicators:

```
📊 CVE Journey Tracker - After Run 2

  ✅ CVE-2024-0001 (example-package)
     State: fixed (confidence: high)
     Fixed in: 1.2.3
     Why: Fixed in version 1.2.3. Fix available from upstream....
     Rule: R2:upstream_fix

  ✅ CVE-2024-0003 (db-handler)
     State: not_applicable (confidence: high)
     Fixed in: 2.0.0
     Why: Marked as not applicable by Echo security team. Reason: Internal classif...
     Rule: R0:csv_override
```

**Note**: After the granularity fix, CVEs only appear once at package-level. NVD data (CVSS scores, rejection status) is denormalized across all package rows with the same CVE.

### SCD2 History Table

Shows state transitions over time:

```
📋 SCD2 History Table - After Run 3

CVE-2024-0004:
   Package            State              From                 To                   Cur Run ID
   ----------------------------------------------------------------------------------------------------
   parser-lib         under_investigation 2026-01-12 12:54:59  2026-01-12 12:57:09      run_20260112_105400
   parser-lib         fixed              2026-01-12 12:57:09  NULL                 ✓   run_20260112_105609
```

This shows CVE-2024-0004 transitioned from `under_investigation` to `fixed` when Run 3 detected the upstream fix.

### State Distribution

Shows overall advisory counts:

```
Current State Distribution:
  under_investigation       38225
  not_applicable             1964
  pending_upstream              3
  fixed                         3
```

## Demo Scenario Explained

The demo tracks 3 mock CVEs through realistic scenarios:

### CVE-2024-0001 (example-package)
- **Run 1-3**: Stays `fixed` - OSV had fix info from the start
- **Demonstrates**: Upstream fix detection on initial load

### CVE-2024-0003 (db-handler)
- **Run 1**: `fixed` - OSV had fix info from the start
- **Run 2**: `not_applicable` - CSV override added by analyst
- **Run 3**: Stays `not_applicable` - CSV override persists
- **Demonstrates**: CSV override priority (overrides upstream fix signal)

### CVE-2024-0004 (parser-lib)
- **Run 1-2**: `under_investigation` - No fix available yet
- **Run 3**: `fixed` - OSV reports new fix (version 3.0.0)
- **Demonstrates**: State transition tracking via SCD2 snapshots

## Architecture Highlights

### Pipeline Stages
1. **Ingestion**: Fetch from Echo data.json, CSV overrides, NVD, and OSV
2. **Transformation**: dbt models enrich, resolve conflicts, and make decisions
3. **Snapshot**: dbt snapshots track state changes (SCD Type 2)
4. **Export**: Output current state as JSON for downstream consumers

### Decision Engine
- **Priority-based**: CSV overrides > NVD rejections > OSV fixes > fallback rules
- **Confidence scoring**: High (upstream fix), Medium (CVSS present), Low (no signals)
- **Explanatory**: Every decision includes reason code and human-readable explanation

### State Tracking
- **dbt snapshots**: Automatic SCD2 implementation
- **History mart**: Maps snapshot output to advisory_state_history table
- **Change detection**: Tracks which CVEs changed state between runs

## Key Features Demonstrated

✅ **Multi-source ingestion** - Combines Echo CSV, NVD, and OSV data
✅ **Conflict resolution** - Priority-based rules handle disagreements
✅ **State transitions** - SCD2 tracking shows CVE lifecycle over time
✅ **Analyst overrides** - CSV overrides have highest priority
✅ **Upstream monitoring** - Detects when fixes become available
✅ **Large-scale processing** - Handles 40k+ CVEs efficiently
✅ **Audit trail** - Every decision is logged with explanation

## Granularity Architecture Fix

### Single Package-Level Granularity
After applying the architecture fix from [ARCHITECTURE_ISSUE_GRANULARITY.md](ARCHITECTURE_ISSUE_GRANULARITY.md):

- **Before**: 40,195 advisories (included duplicate CVE-only entries)
- **After**: 40,192 advisories (3 fewer - CVE-only duplicates removed)

**What Changed:**
- All advisories are now package-level (no NULL package entries)
- NVD data (CVSS scores, rejection status) is denormalized across all packages with the same CVE
- CVEs without package context are excluded (per architecture design)

**Benefits:**
- Single, clear granularity - every advisory is package:CVE
- No duplicate entries to confuse query patterns
- Simple aggregations (no NULL handling needed)
- CSV overrides can target specific packages OR all packages (via CVE-level match)

## Output Files

After running the demo, check:
- `output/advisory_current.json` - Current state of all advisories (40k+ entries)
- `output/run_report_*.md` - Markdown reports for each run
- `advisory_pipeline.duckdb` - Full database with all history

## For Reviewers

This demo shows a production-grade data pipeline with:
- **Correctness**: Priority-based decision engine with clear precedence
- **Auditability**: SCD2 history tracking and explanatory text
- **Scalability**: Processes 40k CVEs in ~1 minute per run
- **Maintainability**: dbt models with clear separation of concerns
- **Extensibility**: Easy to add new sources or decision rules

The visual output makes it easy to verify the system works correctly across different scenarios: initial load, analyst intervention, and upstream fix detection.
