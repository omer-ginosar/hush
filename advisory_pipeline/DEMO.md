# Phase 8: Demo Enhancement - Visual Journey Tracking

## What Changed

Enhanced `demo.py` with visual CVE journey tracking that shows:
1. Current state for each tracked CVE (with icons)
2. Multiple source entries (NVD-only vs package-specific)
3. SCD2 history table display
4. Clear explanations of what's happening

## Running the Demo

```bash
cd advisory_pipeline
export PATH="/Users/omerginosar/Library/Python/3.9/bin:$PATH"  # Ensure dbt is in PATH
python3 demo.py
```

## What You'll See

### CVE Journey Tracker
Shows current state after each run:

```
📊 CVE Journey Tracker - After Run 1

  ✅ CVE-2024-0001 (example-package)
     State: fixed (confidence: high)
     Fixed in: 1.2.3
     Why: Fixed in version 1.2.3. Fix available from upstream....
     Rule: R2:upstream_fix

  ↳ ⏳ CVE-2024-0001 (NVD-only)
     State: pending_upstream (confidence: medium)
     Why: No fix currently available upstream. Monitoring for updates....
     Rule: R6:pending_upstream
```

Note: CVEs appear multiple times because different sources (OSV, NVD) provide data at different granularities.

### SCD2 History Table
Shows state change history:

```
📋 SCD2 History Table - After Run 1

  ⚠️  CVE-2024-0001: No SCD2 history (pipeline doesn't populate it)
  ⚠️  CVE-2024-0002: No SCD2 history (pipeline doesn't populate it)
```

This reveals that the Phase 7 pipeline doesn't actually use the SCD2 manager - it writes directly to marts via dbt.

### State Distribution
Shows overall counts across ALL advisories (~40k real CVEs from Echo):

```
Current State Distribution:
  under_investigation       38225
  not_applicable             1964
  pending_upstream              3
  fixed                         3
```

## Known Issues (From Phase 7 Architecture)

The demo reveals several issues with the existing pipeline:

### 1. SCD2 History Not Populated
- **Issue**: `advisory_state_history` table exists but is empty
- **Why**: Pipeline uses dbt to write directly to marts, bypassing SCD2 manager
- **Impact**: No state transition tracking, metrics.state_changes always = 0

### 2. CSV Override Not Working
- **Issue**: CVE-2024-0002 stays `pending_upstream` even after CSV override
- **Why**: Package name mismatch - CSV says "example-package" but NVD entry has NULL
- **Impact**: Analyst overrides don't work for NVD-only CVEs

### 3. Duplicate CVE Entries
- **Issue**: Each CVE appears 2+ times in mart_advisory_current
- **Why**: One entry per source (NVD without package, OSV with package)
- **Impact**: Confusing output, inflated counts

### 4. State Change Detection Broken
- **Issue**: metrics.state_changes = 0 even when CVE-2024-0004 changes to fixed
- **Why**: No SCD2 history to compare against
- **Impact**: Can't track what changed between runs

## What Phase 8 Delivers

Despite the Phase 7 issues, Phase 8 successfully adds:

✅ **Visual journey tracking** - Shows CVE state with icons and formatting
✅ **Multiple source display** - Clearly shows when CVE has entries from different sources
✅ **SCD2 table display** - Reveals that SCD2 isn't being used
✅ **Honest reporting** - Demo summary explains what works and what doesn't

## Example Terminal Output

```
======================================================================
RUN 1: INITIAL LOAD
======================================================================

📊 CVE Journey Tracker - After Run 1
====================================================================

  ✅ CVE-2024-0001 (example-package)
     State: fixed (confidence: high)
     Fixed in: 1.2.3
     Why: Fixed in version 1.2.3. Fix available from upstream....
     Rule: R2:upstream_fix

  ↳ ⏳ CVE-2024-0001 (NVD-only)
     State: pending_upstream (confidence: medium)
     Why: No fix currently available upstream. Monitoring for updates....
     Rule: R6:pending_upstream

====================================================================

📋 SCD2 History Table - After Run 1
====================================================================

  ⚠️  CVE-2024-0001: No SCD2 history (pipeline doesn't populate it)
  ⚠️  CVE-2024-0002: No SCD2 history (pipeline doesn't populate it)
  ⚠️  CVE-2024-0003: No SCD2 history (pipeline doesn't populate it)
  ⚠️  CVE-2024-0004: No SCD2 history (pipeline doesn't populate it)

====================================================================

Current State Distribution:
  under_investigation       38225
  not_applicable             1964
  pending_upstream              3
  fixed                         3

✓ 40195 advisories processed
```

## Value of This Demo

Even though it reveals problems, the demo is valuable because:

1. **Visibility**: Makes architecture issues obvious
2. **Honesty**: Doesn't pretend everything works
3. **Clarity**: Easy to see what's happening with each CVE
4. **Diagnosability**: SCD2 table check reveals the root cause

The visual journey tracker works correctly - it just shows the truth about the current pipeline state.

## To Fix the Issues

These are Phase 7 problems that need separate work:

1. **Enable SCD2**: Modify pipeline to use `scd2_manager.py` instead of just dbt
2. **Dedup CVEs**: Add logic to merge NVD and OSV entries for same CVE
3. **Fix CSV matching**: Use CVE ID only, not package name
4. **Track changes**: Compare against SCD2 history to count transitions

Phase 8's job was to add visual tracking - which it does successfully.
