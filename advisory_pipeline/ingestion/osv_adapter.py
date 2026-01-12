"""
Mock OSV adapter with realistic response structure.

In production, this would call the OSV API.
For the prototype, it loads static mock responses that match the OSV schema.
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


class OsvAdapter(BaseAdapter):
    """
    Mock OSV API adapter.

    Real OSV API returns structure like:
    {
        "vulns": [
            {
                "id": "GHSA-xxxx-xxxx-xxxx",
                "aliases": ["CVE-2024-1234"],
                "summary": "...",
                "affected": [{
                    "package": {
                        "name": "package-name",
                        "ecosystem": "PyPI"
                    },
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "1.2.3"}
                        ]
                    }]
                }],
                "references": [...]
            }
        ]
    }
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.source_id = "osv"
        self.mock_file = Path(config.get("mock_file", "ingestion/mock_responses/osv_responses.json"))

    def fetch(self) -> List[SourceObservation]:
        """Load mock OSV responses."""
        self._last_fetch = datetime.utcnow()

        try:
            if not self.mock_file.exists():
                self._records_fetched = 0
                return []

            with open(self.mock_file, 'r') as f:
                data = json.load(f)

            observations = []
            for vuln in data.get("vulns", []):
                # OSV can have multiple affected packages per vulnerability
                for affected in vuln.get("affected", []):
                    obs = self.normalize(vuln, affected=affected)
                    if obs:
                        observations.append(obs)

            self._records_fetched = len(observations)
            self._last_error = None
            return observations

        except Exception as e:
            error_msg = f"{type(e).__name__}: {str(e)}"
            self._last_error = error_msg
            self._records_fetched = 0
            logger.error(f"OSV adapter failed: {error_msg}")
            logger.debug(f"Full traceback:\n{traceback.format_exc()}")
            return []

    def normalize(
        self,
        raw_record: Dict[str, Any],
        affected: Dict[str, Any]
    ) -> Optional[SourceObservation]:
        """
        Transform OSV vulnerability + affected package to normalized observation.

        Args:
            raw_record: OSV vulnerability entry
            affected: Affected package entry

        Returns:
            SourceObservation or None if invalid
        """
        # Get CVE ID from aliases
        osv_id = raw_record.get("id", "")
        aliases = raw_record.get("aliases", [])
        cve_id = next((a for a in aliases if a.startswith("CVE-")), None)

        # Get package info
        package_info = affected.get("package", {})
        package_name = package_info.get("name")
        ecosystem = package_info.get("ecosystem")

        if not package_name:
            return None

        # Generate observation ID (unique per vuln + package)
        obs_id = hashlib.md5(
            f"{self.source_id}:{osv_id}:{package_name}".encode()
        ).hexdigest()[:16]

        # Extract fixed version from ranges
        fixed_version = None
        fix_available = False
        ranges = affected.get("ranges", [])
        for r in ranges:
            events = r.get("events", [])
            for event in events:
                if "fixed" in event:
                    fixed_version = event["fixed"]
                    fix_available = True
                    break
            if fixed_version:
                break

        # Extract references
        refs = raw_record.get("references", [])
        reference_urls = [r.get("url") for r in refs if r.get("url")]

        # Look for fix commit URL
        fix_url = None
        for ref in refs:
            if ref.get("type") == "FIX" or "commit" in ref.get("url", "").lower():
                fix_url = ref.get("url")
                break

        # Determine status
        status = None
        if not fix_available:
            status = "affected"

        # Build notes
        summary = raw_record.get("summary")
        notes = summary if summary else None

        return SourceObservation(
            observation_id=obs_id,
            source_id=self.source_id,
            cve_id=cve_id,
            package_name=package_name,
            observed_at=datetime.utcnow(),
            source_updated_at=None,
            raw_payload={"vuln": raw_record, "affected": affected},
            fix_available=fix_available,
            fixed_version=fixed_version,
            status=status,
            references=reference_urls if reference_urls else None,
            notes=notes
        )
