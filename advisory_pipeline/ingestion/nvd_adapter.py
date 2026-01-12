"""
NVD adapter with real API support and optional mock fallback.
"""
import hashlib
import json
import logging
import os
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .base_adapter import BaseAdapter, SourceObservation
from .http_client import CircuitOpenError, HttpClient, RetryConfig

logger = logging.getLogger(__name__)

NVD_MAX_RESULTS_PER_PAGE = 2000


class NvdAdapter(BaseAdapter):
    """NVD API adapter (live with optional mock mode)."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.source_id = "nvd"
        self.use_mock = bool(config.get("use_mock", False))
        self.mock_file = Path(config.get("mock_file", "ingestion/mock_responses/nvd_responses.json"))
        self.base_url = config.get("base_url", "https://services.nvd.nist.gov/rest/json/cves/2.0")
        self.api_key = config.get("api_key") or os.getenv(config.get("api_key_env", "NVD_API_KEY"))
        self.cve_ids = self._normalize_cve_ids(config.get("cve_ids"))
        self.last_mod_start = config.get("last_mod_start")
        self.last_mod_end = config.get("last_mod_end")
        self.days_back = config.get("days_back", 30)
        self.results_per_page = min(
            int(config.get("results_per_page", NVD_MAX_RESULTS_PER_PAGE)),
            NVD_MAX_RESULTS_PER_PAGE,
        )
        self.max_records = config.get("max_records")
        self._validation_failures = 0
        self._validation_sample_limit = config.get("validation_sample_limit", 3)

        self.client = HttpClient(
            source_id=self.source_id,
            rate_limit_per_minute=config.get("rate_limit_per_minute", 300),
            rate_limit_burst=config.get("rate_limit_burst", 10),
            retry_config=RetryConfig(
                max_retries=config.get("max_retries", 5),
                base_delay_seconds=config.get("retry_base_seconds", 1.0),
                max_delay_seconds=config.get("retry_max_seconds", 300.0),
                jitter_ratio=config.get("retry_jitter_ratio", 0.3),
                timeout_seconds=config.get("timeout_seconds", 30.0),
            ),
        )

    def fetch(self) -> List[SourceObservation]:
        """Fetch NVD observations from API or mock file."""
        self._last_fetch = datetime.utcnow()

        try:
            if self.use_mock:
                observations = self._fetch_mock()
            else:
                observations = self._fetch_live()

            self._records_fetched = len(observations)
            self._last_error = None
            return observations

        except Exception as e:
            error_msg = f"{type(e).__name__}: {str(e)}"
            self._last_error = error_msg
            self._records_fetched = 0
            logger.error(f"NVD adapter failed: {error_msg}")
            logger.debug("Full traceback:\n%s", traceback.format_exc())
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
            self._log_validation_failure("missing cve id", raw_record)
            return None

        obs_id = hashlib.md5(f"{self.source_id}:{cve_id}".encode()).hexdigest()[:16]

        # Extract CVSS score
        cvss_score = None
        cvss_vector = None
        metrics = cve_data.get("metrics", {})
        cvss_score, cvss_vector = self._extract_cvss(metrics)

        # Check rejection status
        vuln_status = cve_data.get("vulnStatus", "")
        if vuln_status == "Rejected":
            rejection_status = "rejected"
        elif vuln_status == "Disputed":
            rejection_status = "disputed"
        else:
            rejection_status = "none"

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

        source_updated_at = self._parse_timestamp(
            cve_data.get("lastModified") or raw_record.get("lastModified")
        )

        return SourceObservation(
            observation_id=obs_id,
            source_id=self.source_id,
            cve_id=cve_id,
            package_name=None,  # NVD doesn't have package-level granularity
            observed_at=datetime.utcnow(),
            source_updated_at=source_updated_at,
            raw_payload=raw_record,
            rejection_status=rejection_status,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            references=reference_urls if reference_urls else None,
            notes=notes
        )

    def _log_validation_failure(self, reason: str, payload: Dict[str, Any]) -> None:
        if self._validation_failures < self._validation_sample_limit:
            logger.warning("NVD validation failure (%s): %s", reason, str(payload)[:500])
        self._validation_failures += 1

    def _fetch_mock(self) -> List[SourceObservation]:
        if not self.mock_file.exists():
            self._records_fetched = 0
            return []

        with open(self.mock_file, "r") as handle:
            data = json.load(handle)

        observations: List[SourceObservation] = []
        for vuln in data.get("vulnerabilities", []):
            obs = self.normalize(vuln)
            if obs:
                observations.append(obs)

        return observations

    def _fetch_live(self) -> List[SourceObservation]:
        headers = self._build_headers()
        observations: List[SourceObservation] = []

        for vuln in self._iter_vulnerabilities(headers):
            obs = self.normalize(vuln)
            if obs:
                observations.append(obs)
                if self.max_records and len(observations) >= self.max_records:
                    break

        return observations

    def _iter_vulnerabilities(self, headers: Dict[str, str]) -> Iterable[Dict[str, Any]]:
        if self.cve_ids:
            for cve_id in self.cve_ids:
                params = {"cveId": cve_id}
                data = self._request_page(params, headers)
                for vuln in data.get("vulnerabilities", []):
                    yield vuln
            return

        params = self._build_time_params()
        start_index = 0
        total = None

        while total is None or start_index < total:
            page_params = {
                **params,
                "startIndex": start_index,
                "resultsPerPage": self._results_per_page(),
            }
            data = self._request_page(page_params, headers)
            vulnerabilities = data.get("vulnerabilities", [])
            total = data.get("totalResults", 0)

            if not vulnerabilities:
                break

            for vuln in vulnerabilities:
                yield vuln

            start_index += len(vulnerabilities)

    def _request_page(self, params: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
        try:
            return self.client.get_json(self.base_url, params=params, headers=headers)
        except CircuitOpenError as exc:
            logger.warning("NVD circuit open, skipping request: %s", exc)
            return {}

    def _build_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def _build_time_params(self) -> Dict[str, Any]:
        if self.last_mod_start or self.last_mod_end:
            params = {
                "lastModStartDate": self._format_timestamp(self.last_mod_start),
                "lastModEndDate": self._format_timestamp(self.last_mod_end),
            }
            return {key: value for key, value in params.items() if value is not None}

        if self.days_back:
            end = datetime.now(timezone.utc)
            start = end - timedelta(days=int(self.days_back))
            params = {
                "lastModStartDate": self._format_timestamp(start),
                "lastModEndDate": self._format_timestamp(end),
            }
            return {key: value for key, value in params.items() if value is not None}

        return {}

    def _results_per_page(self) -> int:
        if self.max_records:
            return max(1, min(self.results_per_page, int(self.max_records)))
        return max(1, self.results_per_page)

    @staticmethod
    def _normalize_cve_ids(value: Any) -> Optional[List[str]]:
        if not value:
            return None
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(item) for item in value if item]
        return None

    @staticmethod
    def _format_timestamp(value: Any) -> Optional[str]:
        if not value:
            return None
        if isinstance(value, str):
            return value
        if isinstance(value, datetime):
            ts = value.astimezone(timezone.utc)
            return ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        return None

    @staticmethod
    def _parse_timestamp(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            if value.endswith("Z"):
                value = value[:-1] + "+00:00"
            return datetime.fromisoformat(value)
        except ValueError:
            return None

    @staticmethod
    def _extract_cvss(metrics: Dict[str, Any]) -> tuple[Optional[float], Optional[str]]:
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                return cvss_data.get("baseScore"), cvss_data.get("vectorString")
        return None, None
