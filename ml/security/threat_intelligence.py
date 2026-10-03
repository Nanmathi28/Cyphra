"""Provider-backed threat intelligence evidence, independent of risk decisions."""

from __future__ import annotations

import http.client
import os
import ssl
import threading
import time
from abc import ABC, abstractmethod
from typing import Any

from ml.security.url_security_analyzer import URLInputError, normalize_url


OPENPHISH_FEED_HOST = "raw.githubusercontent.com"
OPENPHISH_FEED_PATH = "/openphish/public_feed/refs/heads/main/feed.txt"
_MAX_FEED_BYTES = 2 * 1024 * 1024


class ThreatIntelligenceProvider(ABC):
    """Interface for providers that inspect one normalized URL."""

    name: str

    @abstractmethod
    def check(self, normalized_url: str) -> dict[str, Any]:
        """Return normalized evidence without making an application decision."""


class OpenPhishCommunityFeedProvider(ThreatIntelligenceProvider):
    """Match against OpenPhish's public community text feed, downloaded locally."""

    name = "openphish_community_feed"

    def __init__(
        self,
        enabled: bool = True,
        timeout_seconds: float = 5.0,
        cache_ttl_seconds: int = 43200,
        failure_retry_seconds: int = 60,
    ):
        self.enabled = enabled
        self.timeout_seconds = max(0.5, float(timeout_seconds))
        self.cache_ttl_seconds = max(0, int(cache_ttl_seconds))
        self.failure_retry_seconds = max(0, int(failure_retry_seconds))
        self._lock = threading.Lock()
        self._feed_urls: set[str] | None = None
        self._feed_loaded_at = 0.0
        self._last_failure_at: float | None = None

    def check(self, normalized_url: str) -> dict[str, Any]:
        try:
            url = normalize_url(normalized_url)
        except URLInputError:
            return _result(self.name, "error", checked=False, details={"reason": "invalid_url"})

        if not self.enabled:
            return _result(self.name, "unavailable", checked=False, details={"reason": "provider_disabled"})

        try:
            feed_urls = self._get_feed_urls()
        except Exception:
            # Keep transport/feed diagnostics out of the response; they can contain
            # environmental details and are not useful to a caller.
            return _result(self.name, "unavailable", checked=False, details={"reason": "feed_unavailable"})

        matched = url in feed_urls
        return _result(
            self.name,
            "matched" if matched else "not_matched",
            checked=True,
            matched=matched,
            category="phishing" if matched else None,
            details={"feed": "OpenPhish Community Feed"} if matched else None,
        )

    def _get_feed_urls(self) -> set[str]:
        now = time.monotonic()
        with self._lock:
            if self._feed_urls is not None and now - self._feed_loaded_at < self.cache_ttl_seconds:
                return self._feed_urls
            if (
                self._last_failure_at is not None
                and now - self._last_failure_at < self.failure_retry_seconds
            ):
                raise OSError("Feed retry cooldown is active")
            try:
                content = self._download_feed()
                urls: set[str] = set()
                for raw_line in content.decode("utf-8-sig").splitlines():
                    line = raw_line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        urls.add(normalize_url(line))
                    except URLInputError:
                        continue
                if not urls:
                    raise ValueError("The feed did not contain valid URL entries")
            except Exception:
                self._last_failure_at = now
                raise
            self._feed_urls = urls
            self._feed_loaded_at = now
            self._last_failure_at = None
            return urls

    def _download_feed(self) -> bytes:
        connection = http.client.HTTPSConnection(
            OPENPHISH_FEED_HOST,
            timeout=self.timeout_seconds,
            context=ssl.create_default_context(),
        )
        try:
            connection.request(
                "GET",
                OPENPHISH_FEED_PATH,
                headers={
                    "User-Agent": "CYPHRA-Threat-Intelligence/1.0",
                    "Accept": "text/plain",
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            if response.status != 200:
                raise OSError("Feed endpoint returned a non-success status")
            content_type = response.getheader("Content-Type", "").lower()
            if "text/plain" not in content_type:
                raise ValueError("Feed endpoint returned an unexpected content type")
            content = response.read(_MAX_FEED_BYTES + 1)
            if len(content) > _MAX_FEED_BYTES:
                raise ValueError("Feed response exceeded the size limit")
            return content
        finally:
            connection.close()


class ThreatIntelligenceAggregator:
    """Query configured providers and return independent, structured evidence."""

    def __init__(self, providers: list[ThreatIntelligenceProvider] | None = None):
        self.providers = list(providers or [])

    @classmethod
    def from_environment(cls) -> "ThreatIntelligenceAggregator":
        return cls([
            OpenPhishCommunityFeedProvider(
                enabled=_env_bool("THREAT_INTEL_OPENPHISH_ENABLED", True),
                timeout_seconds=_env_float("THREAT_INTEL_TIMEOUT_SECONDS", 5.0),
                cache_ttl_seconds=_env_int("THREAT_INTEL_CACHE_TTL_SECONDS", 43200),
            )
        ])

    def check(self, normalized_url: str) -> dict[str, Any]:
        try:
            url = normalize_url(normalized_url)
        except URLInputError:
            return {
                "status": "error",
                "providers": [],
                "matched_providers": [],
                "categories": [],
            }

        results = []
        for provider in self.providers:
            try:
                result = provider.check(url)
                results.append(_normalize_provider_result(provider.name, result))
            except Exception:
                results.append(_result(provider.name, "error", checked=False, details={"reason": "provider_error"}))

        matched_providers = [item["provider"] for item in results if item["matched"]]
        categories = sorted({item["category"] for item in results if item["matched"] and item["category"]})
        if matched_providers:
            status = "matched"
        elif results and all(item["status"] == "not_matched" for item in results):
            status = "not_matched"
        elif any(item["checked"] for item in results):
            status = "partial"
        elif results and all(item["status"] == "error" for item in results):
            status = "error"
        else:
            status = "unavailable"
        return {
            "status": status,
            "providers": results,
            "matched_providers": matched_providers,
            "categories": categories,
        }


def _result(
    provider: str,
    status: str,
    *,
    checked: bool,
    matched: bool = False,
    category: str | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "provider": provider,
        "status": status,
        "checked": checked,
        "matched": matched,
        "category": category,
        "details": details,
    }


def _normalize_provider_result(provider_name: str, result: dict[str, Any]) -> dict[str, Any]:
    status = result.get("status")
    if status not in {"matched", "not_matched", "unavailable", "error"}:
        return _result(provider_name, "error", checked=False, details={"reason": "invalid_provider_result"})
    matched = status == "matched" and result.get("matched") is True
    return _result(
        provider_name,
        status,
        checked=result.get("checked") is True,
        matched=matched,
        category=result.get("category") if matched else None,
        details=result.get("details"),
    )


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default
