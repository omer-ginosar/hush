"""
Ingestion layer for the CVE Advisory Pipeline.

Provides adapters for fetching and normalizing data from multiple sources:
- Echo data.json (base advisory corpus)
- Echo CSV (analyst overrides)
- NVD API (mock)
- OSV API (mock)
"""
from .base_adapter import BaseAdapter, SourceHealth, SourceObservation
from .echo_csv_adapter import EchoCsvAdapter
from .echo_data_adapter import EchoDataAdapter
from .nvd_adapter import NvdAdapter
from .osv_adapter import OsvAdapter

__all__ = [
    "BaseAdapter",
    "SourceObservation",
    "SourceHealth",
    "EchoDataAdapter",
    "EchoCsvAdapter",
    "NvdAdapter",
    "OsvAdapter",
]
