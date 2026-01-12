"""
Mock NVD adapter with realistic response structure.

In production, this would call the NVD API.
For the prototype, it loads static mock responses that match the NVD schema.
"""
import hashlib
import json
import logging
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base_adapter import BaseAdapter, SourceObservation

logger = logging.getLogger(__name__)


class NvdAdapter(BaseAdapter):
    """
    Mock NVD API adapter.

    Real NVD API returns structure like:
    {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "vulnStatus": "Analyzed" | "Rejected",
                    "descriptions": [...],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 7.5,
                                "vectorString": "..."
                            }
                        }]
                    },
                    "references": [...]
                }
            }
        ]
    }
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.source_id = "nvd"
        self.mock_file = Path(config.get("mock_file", "ingestion/mock_responses/nvd_responses.json"))

    def fetch(self) -> List[SourceObservation]:
        """Load mock NVD responses."""
        self._last_fetch = datetime.utcnow()

        try:
            if not self.mock_file.exists():
                self._records_fetched = 0
                return []

            with open(self.mock_file, 'r') as f:
                data = json.load(f)

            observations = []
            for vuln in data.get("vulnerabilities", []):
                obs = self.normalize(vuln)
                if obs:
                    observations.append(obs)

            self._records_fetched = len(observations)
            self._last_error = None
            return observations

        except Exception as e:
            error_msg = f"{type(e).__name__}: {str(e)}"
            self._last_error = error_msg
            self._records_fetched = 0
            logger.error(f"NVD adapter failed: {error_msg}")
            logger.debug(f"Full traceback:\n{traceback.format_exc()}")
            return []

    def normalize(self, raw_record: Dict[str, Any], **kwargs) -> Optional[SourceObservation]:
        """
        Transform NVD vulnerability to normalized observation.

        Args:
            raw_record: NVD vulnerability entry

        Returns:
            SourceObservation or None if invalid
        """
        cve_data = raw_record.get("cve", {})
        cve_id = cve_data.get("id")

        if not cve_id:
            return None

        # Generate observation ID
        obs_id = hashlib.md5(
            f"{self.source_id}:{cve_id}".encode()
        ).hexdigest()[:16]

        # Extract CVSS score
        cvss_score = None
        cvss_vector = None
        metrics = cve_data.get("metrics", {})
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")

        # Check rejection status
        vuln_status = cve_data.get("vulnStatus", "")
        rejection_status = "rejected" if vuln_status == "Rejected" else "none"

        # Extract references
        refs = cve_data.get("references", [])
        reference_urls = [r.get("url") for r in refs if r.get("url")]

        # Extract description
        descriptions = cve_data.get("descriptions", [])
        notes = None
        if descriptions:
            # Prefer English description
            for desc in descriptions:
                if desc.get("lang") == "en":
                    notes = desc.get("value")
                    break
            if not notes and descriptions:
                notes = descriptions[0].get("value")

        return SourceObservation(
            observation_id=obs_id,
            source_id=self.source_id,
            cve_id=cve_id,
            package_name=None,  # NVD doesn't have package-level granularity
            observed_at=datetime.utcnow(),
            source_updated_at=None,
            raw_payload=raw_record,
            rejection_status=rejection_status,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            references=reference_urls if reference_urls else None,
            notes=notes
        )
