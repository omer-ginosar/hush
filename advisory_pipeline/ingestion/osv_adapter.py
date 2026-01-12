"""
OSV adapter with real data dump support and optional mock mode.
"""
import hashlib
import json
import logging
import traceback
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .base_adapter import BaseAdapter, SourceObservation
from .http_client import CircuitOpenError, HttpClient, RetryConfig

logger = logging.getLogger(__name__)


class OsvAdapter(BaseAdapter):
    """OSV adapter backed by data dump or mock fixtures."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.source_id = "osv"
        self.use_mock = bool(config.get("use_mock", False))
        self.mock_file = Path(config.get("mock_file", "ingestion/mock_responses/osv_responses.json"))
        self.data_dump_url = config.get(
            "data_dump_url",
            "https://osv-vulnerabilities.storage.googleapis.com/all.zip",
        )
        self.cache_dir = Path(config.get("cache_dir", "ingestion/cache/osv"))
        self.cache_ttl_hours = config.get("cache_ttl_hours", 24)
        self.max_records = config.get("max_records")
        self.ecosystems = config.get("ecosystems")
        self.ecosystem_set = set(self.ecosystems) if self.ecosystems else None
        self.modified_since = config.get("modified_since")
        self.days_back = config.get("days_back", 30)
        self._validation_failures = 0
        self._validation_sample_limit = config.get("validation_sample_limit", 3)

        self.client = HttpClient(
            source_id=self.source_id,
            rate_limit_per_minute=config.get("rate_limit_per_minute"),
            rate_limit_burst=config.get("rate_limit_burst"),
            retry_config=RetryConfig(
                max_retries=config.get("max_retries", 5),
                base_delay_seconds=config.get("retry_base_seconds", 1.0),
                max_delay_seconds=config.get("retry_max_seconds", 300.0),
                jitter_ratio=config.get("retry_jitter_ratio", 0.3),
                timeout_seconds=config.get("timeout_seconds", 60.0),
            ),
        )

    def fetch(self) -> List[SourceObservation]:
        """Fetch OSV observations from data dump or mock file."""
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
            logger.error(f"OSV adapter failed: {error_msg}")
            logger.debug("Full traceback:\n%s", traceback.format_exc())
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

        if not cve_id and not package_name:
            self._log_validation_failure("missing cve and package", raw_record)
            return None

        obs_id = hashlib.md5(
            f"{self.source_id}:{osv_id}:{package_name or 'none'}".encode()
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

        source_updated_at = self._parse_timestamp(raw_record.get("modified"))

        return SourceObservation(
            observation_id=obs_id,
            source_id=self.source_id,
            cve_id=cve_id,
            package_name=package_name,
            observed_at=datetime.utcnow(),
            source_updated_at=source_updated_at,
            raw_payload={"vuln": raw_record, "affected": affected},
            fix_available=fix_available,
            fixed_version=fixed_version,
            status=status,
            references=reference_urls if reference_urls else None,
            notes=notes
        )

    def _log_validation_failure(self, reason: str, payload: Dict[str, Any]) -> None:
        if self._validation_failures < self._validation_sample_limit:
            logger.warning("OSV validation failure (%s): %s", reason, str(payload)[:500])
        self._validation_failures += 1

    def _fetch_mock(self) -> List[SourceObservation]:
        if not self.mock_file.exists():
            self._records_fetched = 0
            return []

        with open(self.mock_file, "r") as handle:
            data = json.load(handle)

        observations: List[SourceObservation] = []
        for vuln in data.get("vulns", []):
            observations.extend(self._normalize_vuln(vuln))

        return observations

    def _fetch_live(self) -> List[SourceObservation]:
        zip_path = self.cache_dir / "osv_all.zip"
        if self._cache_expired(zip_path):
            try:
                self._download_dump(zip_path)
            except Exception as exc:
                if zip_path.exists():
                    logger.warning("OSV download failed, using cached data: %s", exc)
                else:
                    raise

        observations: List[SourceObservation] = []
        for vuln in self._iter_dump_records(zip_path):
            for obs in self._normalize_vuln(vuln):
                observations.append(obs)
                if self.max_records and len(observations) >= self.max_records:
                    return observations

        return observations

    def _normalize_vuln(self, vuln: Dict[str, Any]) -> List[SourceObservation]:
        observations: List[SourceObservation] = []
        affected_entries = vuln.get("affected") or [{}]

        for affected in affected_entries:
            obs = self.normalize(vuln, affected=affected)
            if obs:
                observations.append(obs)

        return observations

    def _cache_expired(self, zip_path: Path) -> bool:
        if not zip_path.exists():
            return True
        if not self.cache_ttl_hours:
            return False

        mtime = datetime.fromtimestamp(zip_path.stat().st_mtime, tz=timezone.utc)
        return datetime.now(timezone.utc) - mtime > timedelta(hours=int(self.cache_ttl_hours))

    def _download_dump(self, zip_path: Path) -> None:
        try:
            self.client.download_to_file(self.data_dump_url, zip_path)
        except CircuitOpenError as exc:
            logger.warning("OSV circuit open, using existing cache if present: %s", exc)
            if not zip_path.exists():
                raise

    def _iter_dump_records(self, zip_path: Path) -> Iterable[Dict[str, Any]]:
        with zipfile.ZipFile(zip_path, "r") as archive:
            for info in archive.infolist():
                if info.is_dir() or not info.filename.endswith(".json"):
                    continue
                if self._should_skip_path(info.filename):
                    continue

                with archive.open(info) as handle:
                    try:
                        vuln = json.load(handle)
                    except json.JSONDecodeError:
                        continue

                if self._should_skip_vuln(vuln):
                    continue

                yield vuln

    def _should_skip_path(self, filename: str) -> bool:
        if not self.ecosystem_set:
            return False
        if "/" not in filename:
            return False
        prefix = filename.split("/", 1)[0]
        return prefix not in self.ecosystem_set

    def _should_skip_vuln(self, vuln: Dict[str, Any]) -> bool:
        if self.ecosystem_set:
            ecosystems = {entry.get("package", {}).get("ecosystem") for entry in vuln.get("affected", [])}
            ecosystems.discard(None)
            if ecosystems and ecosystems.isdisjoint(self.ecosystem_set):
                return True

        modified_since = self._modified_since()
        if modified_since:
            modified_at = self._parse_timestamp(vuln.get("modified"))
            if modified_at and modified_at < modified_since:
                return True

        return False

    def _modified_since(self) -> Optional[datetime]:
        if self.modified_since:
            return self._parse_timestamp(self.modified_since)
        if self.days_back:
            return datetime.now(timezone.utc) - timedelta(days=int(self.days_back))
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
