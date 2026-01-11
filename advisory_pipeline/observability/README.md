# Observability Layer

Phase 6 implementation for the CVE Advisory Pipeline prototype.

## Purpose

The observability layer provides **metrics collection**, **data quality checks**, and **reporting** for pipeline runs. It answers questions like:

- How many advisories were processed?
- What state transitions occurred?
- Which rules fired most frequently?
- Are there data quality issues?
- Is source data healthy?

## Architecture

```
observability/
├── metrics.py         # RunMetrics dataclass for tracking run statistics
├── quality_checks.py  # SQL-based data quality validation
├── reporter.py        # Markdown report generation
└── README.md          # This file
```

## Components

### 1. RunMetrics (`metrics.py`)

Tracks all metrics for a single pipeline run:

- **Counts**: Total advisories, processed, state changes, errors
- **State distribution**: Current snapshot of advisory states
- **Transitions**: Which state changes occurred (from_state → to_state)
- **Rules fired**: Which decision rules were used
- **Source health**: Health status of each data source
- **Quality issues**: Errors encountered during the run

**Usage:**

```python
from observability import RunMetrics

metrics = RunMetrics(run_id="run_20240115_120000", started_at=datetime.utcnow())
metrics.record_transition("pending_upstream", "fixed")
metrics.record_rule_fired("R2:upstream_fix")
metrics.advisories_processed += 1

# Serialize for storage
metrics_dict = metrics.to_dict()
```

### 2. QualityChecker (`quality_checks.py`)

Runs SQL-based validation checks against pipeline outputs:

- **no_null_states**: Every advisory must have a state
- **explanation_completeness**: All advisories must have explanations
- **fixed_has_version**: "fixed" state must include fixed_version
- **cve_format**: CVE IDs must match CVE-YYYY-NNNN pattern
- **stalled_cves**: Detect advisories stuck in non-final states >90 days
- **no_orphan_packages**: Placeholder for package registry validation

**Usage:**

```python
from observability import QualityChecker

checker = QualityChecker(database)
results = checker.run_all_checks()

for result in results:
    print(f"{result.check_name}: {'PASS' if result.passed else 'FAIL'} - {result.message}")
```

### 3. RunReporter (`reporter.py`)

Generates human-readable Markdown reports from metrics and quality check results:

- Run metadata (ID, timestamp, duration)
- Summary statistics table
- State distribution
- State transitions
- Rules fired
- Quality check results
- Source health status

**Usage:**

```python
from observability import RunReporter

reporter = RunReporter()
report_md = reporter.generate_report(metrics, quality_results)
report_path = reporter.save_report(report_md, Path("output"))
print(f"Report saved to: {report_path}")
```

## Integration Points

The observability layer is called by the main pipeline orchestrator (`run_pipeline.py`):

1. **Run start**: Create RunMetrics instance
2. **During ingestion**: Record source health
3. **During SCD2 updates**: Record transitions and rule firing
4. **After dbt run**: Run quality checks
5. **Run end**: Generate and save report

## Output

### Metrics Storage

Metrics are serialized to JSON and stored in the `pipeline_runs` table:

```sql
SELECT * FROM pipeline_runs WHERE run_id = 'run_20240115_120000';
```

### Reports

Markdown reports are saved to `output/run_report_YYYYMMDD_HHMMSS.md`:

```markdown
# Pipeline Run Report
**Run ID:** run_20240115_120000
**Duration:** 12.3 seconds

## Summary
| Metric            | Value |
|-------------------|-------|
| Total Advisories  | 150   |
| State Changes     | 23    |
| Errors            | 0     |

## State Distribution
| State              | Count |
|--------------------|-------|
| fixed              | 45    |
| pending_upstream   | 78    |
| not_applicable     | 27    |
```

## Design Decisions

### Why SQL-based quality checks?

- **Performance**: Checks run directly in database, avoiding Python loops
- **Simplicity**: Single SQL query per check, easy to understand and modify
- **Extensibility**: New checks are just new SQL queries

### Why Markdown reports?

- **Human-readable**: Plain text, readable without rendering
- **Version control friendly**: Text diffs show report changes over time
- **Tool-agnostic**: Works in GitHub, GitLab, terminals, editors

### Why tabulate for formatting?

- **Clean tables**: GitHub-flavored Markdown tables with proper alignment
- **Minimal dependency**: Small, stable library with single purpose
- **Readable code**: Simple API, no complex formatting logic

## Extension Points

### Adding new quality checks

Add a new method to `QualityChecker`:

```python
def check_custom_rule(self) -> QualityCheckResult:
    conn = self.db.connect()
    result = conn.execute("SELECT count(*) FROM ... WHERE ...").fetchone()[0]

    return QualityCheckResult(
        check_name="custom_rule",
        passed=result == 0,
        message=f"Found {result} violations" if result > 0 else "All good",
        details={"violation_count": result}
    )
```

Then add it to `run_all_checks()`:

```python
def run_all_checks(self):
    results = []
    results.append(self.check_no_null_states())
    results.append(self.check_custom_rule())  # <-- Add here
    return results
```

### Adding new metrics

Add new fields to the `RunMetrics` dataclass:

```python
@dataclass
class RunMetrics:
    # Existing fields...
    custom_metric: int = 0
```

Update `to_dict()` to include the new field:

```python
def to_dict(self):
    return {
        # Existing fields...
        "custom_metric": self.custom_metric,
    }
```

### Customizing report format

Modify `RunReporter.generate_report()` to add new sections or change formatting.

## Known Limitations

1. **No alerting**: Reports are written to files but not sent anywhere. In production, integrate with alerting systems (email, Slack, PagerDuty).

2. **No trend analysis**: Each report is standalone. Consider adding historical comparison in production.

3. **No orphan package check**: Requires a package registry that doesn't exist in the prototype.

4. **Fixed thresholds**: Stalled CVE threshold (90 days, 10 CVEs) is hardcoded. Make configurable in production.

## Follow-up Work

For production deployment, consider:

- **Metrics export**: Send metrics to Prometheus, CloudWatch, or Datadog
- **Alert routing**: Failed quality checks should trigger alerts
- **Historical trends**: Track metrics over time to detect degradation
- **Custom dashboards**: Build visual dashboards from metrics
- **Performance tracking**: Add query timing and dbt model performance metrics
