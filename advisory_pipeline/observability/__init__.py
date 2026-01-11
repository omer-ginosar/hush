"""
Observability layer for the advisory pipeline.

This module provides metrics collection, quality checks, and reporting
for pipeline runs.

Main exports:
- RunMetrics: Tracks metrics for a pipeline run
- QualityChecker: Runs data quality checks
- QualityCheckResult: Result of a quality check
- RunReporter: Generates Markdown reports
"""
from .metrics import RunMetrics
from .quality_checks import QualityChecker, QualityCheckResult
from .reporter import RunReporter

__all__ = [
    "RunMetrics",
    "QualityChecker",
    "QualityCheckResult",
    "RunReporter",
]
