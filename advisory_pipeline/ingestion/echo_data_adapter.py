"""
Adapter for Echo's data.json - the base advisory corpus.

This represents Echo's published advisories before enrichment.
The data.json structure is: {package_name: {cve_id: {fixed_version: ...}}}
"""
import hashlib
import json
import logging
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from .base_adapter import BaseAdapter, SourceObservation

logger = logging.getLogger(__name__)


class EchoDataAdapter(BaseAdapter):
    """
    Loads Echo's data.json advisory corpus.

    Expected structure:
    {
        "package-name": {
            "CVE-2024-1234": {
                "fixed_version": "1.2.3-1"
            },
            "CVE-2024-5678": {}
        }
    }
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.source_id = "echo_data"
        self.url = config.get("url")
        self.cache_path = Path(config.get("cache_path", "data.json"))

    def fetch(self) -> List[SourceObservation]:
        """Load data.json from cache or URL."""
        self._last_fetch = datetime.utcnow()

        try:
            data = self._load_data()
            observations = []

            for package_name, cves in data.items():
                if not isinstance(cves, dict):
                    continue

                for cve_id, cve_data in cves.items():
                    obs = self.normalize(cve_data, package_name=package_name, cve_id=cve_id)
                    if obs:
                        observations.append(obs)

            self._records_fetched = len(observations)
            self._last_error = None
            return observations

        except Exception as e:
            error_msg = f"{type(e).__name__}: {str(e)}"
            self._last_error = error_msg
            self._records_fetched = 0
            logger.error(f"Echo data adapter failed: {error_msg}")
            logger.debug(f"Full traceback:\n{traceback.format_exc()}")
            return []

    def _load_data(self) -> Dict[str, Any]:
        """Load from cache, falling back to URL if needed."""
        if self.cache_path.exists():
            with open(self.cache_path, 'r') as f:
                return json.load(f)

        # Try URL if no cache and URL is configured
        if self.url:
            response = requests.get(self.url, timeout=30)
            response.raise_for_status()
            data = response.json()

            # Cache for future use
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_path, 'w') as f:
                json.dump(data, f)

            return data

        raise FileNotFoundError(f"No cache at {self.cache_path} and no URL configured")

    def normalize(
        self,
        raw_record: Dict[str, Any],
        package_name: str,
        cve_id: str
    ) -> Optional[SourceObservation]:
        """
        Transform Echo advisory to normalized observation.

        Args:
            raw_record: CVE data (may be empty dict)
            package_name: Package identifier
            cve_id: CVE identifier

        Returns:
            SourceObservation or None if invalid
        """
        # Validate CVE ID format
        if not cve_id or not cve_id.startswith("CVE-"):
            return None

        # Generate stable observation ID
        obs_id = hashlib.md5(
            f"{self.source_id}:{package_name}:{cve_id}".encode()
        ).hexdigest()[:16]

        # Extract fixed version if present
        fixed_version = raw_record.get("fixed_version") if isinstance(raw_record, dict) else None

        # Determine status
        status = None
        fix_available = None
        if fixed_version:
            status = "fixed"
            fix_available = True

        return SourceObservation(
            observation_id=obs_id,
            source_id=self.source_id,
            cve_id=cve_id,
            package_name=package_name,
            observed_at=datetime.utcnow(),
            source_updated_at=None,  # data.json doesn't have per-record timestamps
            raw_payload=raw_record if isinstance(raw_record, dict) else {},
            status=status,
            fix_available=fix_available,
            fixed_version=fixed_version,
            notes=None
        )
