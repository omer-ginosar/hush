"""
Base adapter interface for all source adapters.

Defines the contract that all source adapters must implement and provides
shared data models for normalized observations.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class SourceObservation:
    """
    Normalized observation from any source.

    This is the canonical format that all adapters must produce.
    It abstracts away source-specific schemas into a uniform representation.
    """
    # Core identifiers
    observation_id: str           # Unique ID for this observation
    source_id: str                # nvd | osv | echo_csv | echo_data
    cve_id: Optional[str]         # CVE-YYYY-NNNNN or None
    package_name: Optional[str]   # Package name in source's namespace

    # Temporal metadata
    observed_at: datetime         # When we fetched this
    source_updated_at: Optional[datetime] = None  # When source says it was updated

    # Raw data
    raw_payload: Dict[str, Any] = field(default_factory=dict)

    # Normalized signals (all optional, sources provide what they have)
    fix_available: Optional[bool] = None
    fixed_version: Optional[str] = None
    affected_versions: Optional[str] = None  # Version range expression
    status: Optional[str] = None  # affected | not_affected | under_investigation
    rejection_status: Optional[str] = None  # none | rejected | disputed
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    exploit_available: Optional[bool] = None
    references: Optional[List[str]] = None
    notes: Optional[str] = None


@dataclass
class SourceHealth:
    """Health status of a source adapter."""
    source_id: str
    is_healthy: bool
    last_fetch: Optional[datetime]
    records_fetched: int
    error_message: Optional[str] = None


class BaseAdapter(ABC):
    """
    Abstract base class for source adapters.

    All adapters must implement fetch() and normalize().
    Provides shared health check functionality.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.source_id: str = ""
        self._last_fetch: Optional[datetime] = None
        self._last_error: Optional[str] = None
        self._records_fetched: int = 0

    @abstractmethod
    def fetch(self) -> List[SourceObservation]:
        """
        Fetch all records from source and return normalized observations.

        Returns:
            List of SourceObservation objects
        """
        pass

    @abstractmethod
    def normalize(self, raw_record: Dict[str, Any], **kwargs) -> Optional[SourceObservation]:
        """
        Transform a raw source record to normalized observation.

        Args:
            raw_record: Raw data from source
            **kwargs: Additional context (e.g., package_name for NVD)

        Returns:
            SourceObservation or None if record is invalid
        """
        pass

    def get_health(self) -> SourceHealth:
        """Return health status of this adapter."""
        return SourceHealth(
            source_id=self.source_id,
            is_healthy=self._last_error is None,
            last_fetch=self._last_fetch,
            records_fetched=self._records_fetched,
            error_message=self._last_error
        )
