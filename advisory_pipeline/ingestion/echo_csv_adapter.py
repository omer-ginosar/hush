"""
Adapter for Echo's internal CSV overrides.

These represent analyst decisions that override upstream sources.
Expected CSV columns: cve_id, package, status, fixed_version, internal_status
"""
import csv
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base_adapter import BaseAdapter, SourceObservation


class EchoCsvAdapter(BaseAdapter):
    """
    Loads Echo's internal CSV with analyst overrides.

    Expected CSV columns:
    - cve_id: CVE identifier
    - package: Package identifier
    - status: not_applicable | wont_fix | fixed
    - fixed_version: Fixed version (if applicable)
    - internal_status: Internal classification (e.g., code_not_in_use)
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.source_id = "echo_csv"
        self.path = Path(config.get("path", "advisory_not_applicable.csv"))
        self._previous_hash: Optional[str] = None

    def fetch(self) -> List[SourceObservation]:
        """Load CSV and return observations."""
        self._last_fetch = datetime.utcnow()

        try:
            if not self.path.exists():
                # Return empty if no CSV exists yet
                self._records_fetched = 0
                return []

            observations = []
            with open(self.path, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    obs = self.normalize(row)
                    if obs:
                        observations.append(obs)

            self._records_fetched = len(observations)
            self._last_error = None
            return observations

        except Exception as e:
            self._last_error = str(e)
            self._records_fetched = 0
            return []

    def normalize(self, raw_record: Dict[str, Any], **kwargs) -> Optional[SourceObservation]:
        """
        Transform CSV row to normalized observation.

        Args:
            raw_record: CSV row as dictionary

        Returns:
            SourceObservation or None if invalid
        """
        cve_id = raw_record.get("cve_id", "").strip()
        package_name = raw_record.get("package", "").strip()

        if not cve_id or not package_name:
            return None

        # Validate CVE ID format
        if not cve_id.startswith("CVE-"):
            return None

        # Generate stable observation ID
        obs_id = hashlib.md5(
            f"{self.source_id}:{package_name}:{cve_id}".encode()
        ).hexdigest()[:16]

        # Extract fields
        status = raw_record.get("status", "").strip().lower()
        fixed_version = raw_record.get("fixed_version", "").strip() or None
        internal_status = raw_record.get("internal_status", "").strip()

        # Build notes from internal_status
        notes = f"Internal classification: {internal_status}" if internal_status else None

        return SourceObservation(
            observation_id=obs_id,
            source_id=self.source_id,
            cve_id=cve_id,
            package_name=package_name,
            observed_at=datetime.utcnow(),
            source_updated_at=None,  # CSV doesn't have timestamps
            raw_payload=raw_record,
            status=status if status else None,
            fixed_version=fixed_version,
            notes=notes
        )

    def get_content_hash(self) -> Optional[str]:
        """Get hash of CSV contents for change detection."""
        if not self.path.exists():
            return None

        with open(self.path, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()

    def has_changed(self) -> bool:
        """Check if CSV has changed since last fetch."""
        current_hash = self.get_content_hash()
        changed = current_hash != self._previous_hash
        self._previous_hash = current_hash
        return changed
