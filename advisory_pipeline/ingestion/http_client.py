"""
HTTP utilities for source adapters.

Provides rate limiting, retries with backoff, circuit breaking, and
lightweight in-run response caching.
"""
import logging
import random
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


class CircuitOpenError(RuntimeError):
    """Raised when the circuit breaker is open."""


@dataclass
class RetryConfig:
    max_retries: int = 5
    base_delay_seconds: float = 1.0
    max_delay_seconds: float = 300.0
    jitter_ratio: float = 0.3
    timeout_seconds: float = 30.0


class RateLimiter:
    """Simple token bucket rate limiter."""

    def __init__(self, rate_per_minute: Optional[int], burst: Optional[int]):
        self.rate_per_minute = rate_per_minute
        self.burst = burst
        self._tokens = burst if burst else 0
        self._last_refill = time.monotonic()

    def acquire(self) -> None:
        if not self.rate_per_minute or not self.burst:
            return

        self._refill()
        if self._tokens < 1:
            wait_seconds = (1 - self._tokens) / (self.rate_per_minute / 60.0)
            time.sleep(wait_seconds)
            self._refill()

        self._tokens -= 1

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        refill_rate = self.rate_per_minute / 60.0
        self._tokens = min(self.burst, self._tokens + elapsed * refill_rate)
        self._last_refill = now


class CircuitBreaker:
    """Basic circuit breaker with half-open probe."""

    def __init__(self, failure_threshold: int = 5, open_seconds: int = 900):
        self.failure_threshold = failure_threshold
        self.open_seconds = open_seconds
        self._failure_count = 0
        self._opened_at: Optional[float] = None
        self._half_open = False

    def can_attempt(self) -> bool:
        if self._opened_at is None:
            return True

        if time.monotonic() - self._opened_at >= self.open_seconds:
            if not self._half_open:
                self._half_open = True
                return True
            return False

        return False

    def record_success(self) -> None:
        self._failure_count = 0
        self._opened_at = None
        self._half_open = False

    def record_failure(self) -> None:
        self._failure_count += 1
        if self._failure_count >= self.failure_threshold:
            self._opened_at = time.monotonic()
            self._half_open = False


class HttpClient:
    """HTTP client with retries, rate limiting, circuit breaking, and caching."""

    def __init__(
        self,
        source_id: str,
        rate_limit_per_minute: Optional[int] = None,
        rate_limit_burst: Optional[int] = None,
        retry_config: Optional[RetryConfig] = None,
        circuit_breaker: Optional[CircuitBreaker] = None,
        cache_enabled: bool = True,
    ):
        self.source_id = source_id
        self.session = requests.Session()
        self.retry_config = retry_config or RetryConfig()
        self.rate_limiter = RateLimiter(rate_limit_per_minute, rate_limit_burst)
        self.circuit_breaker = circuit_breaker or CircuitBreaker()
        self.cache_enabled = cache_enabled
        self._cache: Dict[Tuple[str, Tuple[Tuple[str, Any], ...]], Any] = {}

    def get_json(self, url: str, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        cache_key = self._cache_key(url, params)
        if self.cache_enabled and cache_key in self._cache:
            return self._cache[cache_key]

        response = self._request("GET", url, params=params, headers=headers, stream=False)
        payload = response.json()

        if self.cache_enabled:
            self._cache[cache_key] = payload

        return payload

    def download_to_file(self, url: str, destination: Path, headers: Optional[Dict[str, str]] = None) -> None:
        response = self._request("GET", url, headers=headers, stream=True)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temp_path = destination.with_suffix(destination.suffix + ".part")

        with open(temp_path, "wb") as handle:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    handle.write(chunk)

        temp_path.replace(destination)

    def _request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        stream: bool = False,
    ) -> requests.Response:
        if not self.circuit_breaker.can_attempt():
            raise CircuitOpenError(f"{self.source_id} circuit open")

        last_error: Optional[Exception] = None

        for attempt in range(self.retry_config.max_retries + 1):
            self.rate_limiter.acquire()
            try:
                response = self.session.request(
                    method,
                    url,
                    params=params,
                    headers=headers,
                    timeout=self.retry_config.timeout_seconds,
                    stream=stream,
                )
            except requests.RequestException as exc:
                last_error = exc
                if attempt < self.retry_config.max_retries:
                    self._sleep_with_backoff(attempt, None)
                    continue
                self.circuit_breaker.record_failure()
                raise

            if response.status_code in RETRYABLE_STATUS_CODES:
                last_error = requests.HTTPError(f"HTTP {response.status_code}")
                if attempt < self.retry_config.max_retries:
                    retry_after = self._retry_after_seconds(response)
                    self._sleep_with_backoff(attempt, retry_after)
                    continue
                self.circuit_breaker.record_failure()
                response.raise_for_status()

            if response.status_code >= 400:
                self.circuit_breaker.record_failure()
                response.raise_for_status()

            self.circuit_breaker.record_success()
            return response

        self.circuit_breaker.record_failure()
        raise last_error if last_error else RuntimeError("HTTP request failed")

    def _cache_key(self, url: str, params: Optional[Dict[str, Any]]) -> Tuple[str, Tuple[Tuple[str, Any], ...]]:
        params_tuple = tuple(sorted((params or {}).items()))
        return url, params_tuple

    def _retry_after_seconds(self, response: requests.Response) -> Optional[float]:
        value = response.headers.get("Retry-After")
        if not value:
            return None

        try:
            return float(value)
        except ValueError:
            try:
                dt = parsedate_to_datetime(value)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return max(0.0, (dt - datetime.now(timezone.utc)).total_seconds())
            except (TypeError, ValueError):
                logger.debug("Unable to parse Retry-After header: %s", value)
                return None

    def _sleep_with_backoff(self, attempt: int, retry_after: Optional[float]) -> None:
        base = min(
            self.retry_config.max_delay_seconds,
            self.retry_config.base_delay_seconds * (2 ** attempt),
        )
        jitter = base * random.uniform(0, self.retry_config.jitter_ratio)
        delay = base + jitter
        if retry_after is not None:
            delay = max(delay, retry_after)
        time.sleep(delay)
