"""
Generate human-readable run reports in Markdown format.

This module provides RunReporter, which transforms RunMetrics and quality check
results into formatted Markdown reports for human consumption.

Report sections:
- Header with run metadata (ID, timestamp, duration)
- Summary table with core metrics
- State distribution showing current advisory states
- State transitions that occurred in the run
- Rules fired and their frequency
- Data quality check results
- Source health status

Design decisions:
- Markdown output for readability and version control friendliness
- Uses tabulate library for clean table formatting (GitHub-flavored)
- Reports saved with timestamp for historical tracking
- Minimal formatting - focus on clarity over aesthetics
"""
from datetime import datetime
from typing import List
from pathlib import Path
from tabulate import tabulate

from .metrics import RunMetrics
from .quality_checks import QualityCheckResult


class RunReporter:
    """
    Generates human-readable Markdown reports from pipeline run metrics.

    Reports are designed to be:
    - Readable as plain text
    - Renderable as Markdown in GitHub/GitLab
    - Suitable for archiving and comparison across runs
    """

    def generate_report(
        self,
        metrics: RunMetrics,
        quality_results: List[QualityCheckResult]
    ) -> str:
        """
        Generate full run report in Markdown format.

        Args:
            metrics: RunMetrics object from completed pipeline run
            quality_results: List of quality check results

        Returns:
            Markdown-formatted report as string
        """
        lines = []

        # Header
        lines.append("# Pipeline Run Report")
        lines.append(f"**Run ID:** {metrics.run_id}")
        lines.append(f"**Started:** {metrics.started_at.isoformat()}")
        if metrics.completed_at:
            duration = (metrics.completed_at - metrics.started_at).total_seconds()
            lines.append(f"**Duration:** {duration:.1f} seconds")
        lines.append("")

        # Summary table
        lines.append("## Summary")
        summary_data = [
            ["Total Advisories", metrics.advisories_total],
            ["Processed", metrics.advisories_processed],
            ["State Changes", metrics.state_changes],
            ["Errors", metrics.errors],
        ]
        lines.append(tabulate(summary_data, headers=["Metric", "Value"], tablefmt="github"))
        lines.append("")

        # State distribution
        if metrics.state_counts:
            lines.append("## State Distribution")
            state_data = [[k, v] for k, v in sorted(metrics.state_counts.items())]
            lines.append(tabulate(state_data, headers=["State", "Count"], tablefmt="github"))
            lines.append("")

        # Transitions
        if metrics.transitions:
            lines.append("## State Transitions")
            trans_data = [[f"{k[0]} → {k[1]}", v] for k, v in metrics.transitions.items()]
            lines.append(tabulate(trans_data, headers=["Transition", "Count"], tablefmt="github"))
            lines.append("")

        # Rules fired
        if metrics.rules_fired:
            lines.append("## Rules Fired")
            rules_data = [[k, v] for k, v in sorted(metrics.rules_fired.items())]
            lines.append(tabulate(rules_data, headers=["Rule", "Count"], tablefmt="github"))
            lines.append("")

        # Quality checks
        lines.append("## Data Quality Checks")
        quality_data = []
        for qr in quality_results:
            status = "✓" if qr.passed else "✗"
            quality_data.append([status, qr.check_name, qr.message])
        lines.append(tabulate(quality_data, headers=["Status", "Check", "Details"], tablefmt="github"))
        lines.append("")

        # Source health
        if metrics.source_health:
            lines.append("## Source Health")
            health_data = []
            for source, health in metrics.source_health.items():
                status = "✓" if health.get("healthy", False) else "✗"
                records = health.get("records", 0)
                health_data.append([status, source, records])
            lines.append(tabulate(health_data, headers=["Status", "Source", "Records"], tablefmt="github"))
            lines.append("")

        return "\n".join(lines)

    def save_report(self, report: str, output_dir: Path) -> Path:
        """
        Save report to file with timestamp.

        Args:
            report: Markdown report content
            output_dir: Directory to save report in

        Returns:
            Path to saved report file
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        filepath = output_dir / f"run-report-{timestamp}.md"
        filepath.write_text(report)
        return filepath
