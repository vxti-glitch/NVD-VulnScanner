"""
scanner.nvd_client
==================
Async NVD API v2 client with rate-limit-aware concurrency, exponential
backoff retry, and CVSS version fallback hierarchy.

Design notes (Backend Architect)
---------------------------------
Rate limiting strategy
~~~~~~~~~~~~~~~~~~~~~~
NVD enforces a rolling 30-second window:
  - Unauthenticated : 5 requests / 30 s  → 1 request per 6.0 s
  - Authenticated   : 50 requests / 30 s → 1 request per 0.6 s

Implementation uses asyncio.Semaphore to bound concurrent in-flight
requests plus a per-request sleep of (window / rate_limit) seconds.
The semaphore size equals the rate limit so we can burst up to the
limit while the sleep prevents sustained throughput from exceeding it.

A Semaphore(1) + 6s sleep gives identical throughput to a full rate-
limit-window approach but is simpler to reason about and immune to
clock drift issues.

Retry strategy
~~~~~~~~~~~~~~
HTTP 429 (Too Many Requests) and transient network errors trigger
exponential backoff: delay = base_delay * 2^attempt, capped at 60 s.
A 503 Service Unavailable is also retried — NVD maintenance windows
are common. Other 4xx errors are not retried.

CVSS fallback
~~~~~~~~~~~~~
NVD API v2 returns metrics keyed by version. Priority:
  1. cvssMetricV31  (CVSS 3.1 — most current)
  2. cvssMetricV30  (CVSS 3.0)
  3. cvssMetricV2   (CVSS 2.0 — legacy, baseSeverity is on the outer object)

All three are mapped to a normalised (score, severity, vector, version)
tuple so downstream code never needs to branch on metric version.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import aiohttp

from .models import CVERecord, SoftwareAsset

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# NVD API constants
# ---------------------------------------------------------------------------
_NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_RATE_WINDOW = 30          # seconds — NVD rolling window
_UNAUTH_LIMIT = 5          # requests per window, unauthenticated
_AUTH_LIMIT = 50           # requests per window, with API key
_MAX_RESULTS = 20          # CVEs to retrieve per CPE
_RETRY_ATTEMPTS = 4        # total attempts (1 initial + 3 retries)
_RETRY_BASE_DELAY = 2.0    # seconds — first retry wait
_RETRY_MAX_DELAY = 60.0    # seconds — backoff ceiling
_REQUEST_TIMEOUT = 30      # seconds — per-request TCP timeout


# ---------------------------------------------------------------------------
# CVSS extraction helper
# ---------------------------------------------------------------------------
def _extract_cvss(
    metrics: dict[str, Any],
) -> tuple[float, str, str, str]:
    """Extract the highest-priority CVSS score from the NVD metrics block.

    Returns
    -------
    tuple[float, str, str, str]
        (base_score, severity, vector_string, cvss_version)
    """
    for key, version_label in (
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
    ):
        if key in metrics and metrics[key]:
            data = metrics[key][0].get("cvssData", {})
            return (
                float(data.get("baseScore", 0.0)),
                data.get("baseSeverity", "UNKNOWN").upper(),
                data.get("vectorString", "N/A"),
                version_label,
            )

    if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        entry = metrics["cvssMetricV2"][0]
        data = entry.get("cvssData", {})
        # In CVSS v2, baseSeverity lives on the outer object, not cvssData
        severity = entry.get("baseSeverity", "UNKNOWN").upper()
        return (
            float(data.get("baseScore", 0.0)),
            severity,
            data.get("vectorString", "N/A"),
            "2.0",
        )

    return 0.0, "UNKNOWN", "N/A", "UNKNOWN"


# ---------------------------------------------------------------------------
# NVD API client
# ---------------------------------------------------------------------------
class NVDClient:
    """Async NVD API v2 client.

    Usage
    -----
    async with NVDClient(api_key="...") as client:
        cves = await client.scan_assets(assets)
    """

    def __init__(
        self,
        api_key: str | None = None,
        max_results: int = _MAX_RESULTS,
    ) -> None:
        self._api_key = api_key
        self._max_results = max_results

        # Rate limiting
        rate_limit = _AUTH_LIMIT if api_key else _UNAUTH_LIMIT
        self._inter_request_delay = _RATE_WINDOW / rate_limit
        # Semaphore(1) serialises requests; delay paces them within the window.
        # This is more conservative than bursting but is reliable across NVD
        # maintenance periods where the server is slow to reset counters.
        self._semaphore = asyncio.Semaphore(1)

        self._session: aiohttp.ClientSession | None = None

    # ------------------------------------------------------------------
    # Context manager — manages aiohttp session lifecycle
    # ------------------------------------------------------------------
    async def __aenter__(self) -> "NVDClient":
        timeout = aiohttp.ClientTimeout(total=_REQUEST_TIMEOUT)
        headers: dict[str, str] = {"Accept": "application/json"}
        if self._api_key:
            headers["apiKey"] = self._api_key
        self._session = aiohttp.ClientSession(
            headers=headers,
            timeout=timeout,
        )
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._session:
            await self._session.close()
            self._session = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------
    async def scan_assets(
        self, assets: list[SoftwareAsset]
    ) -> list[CVERecord]:
        """Query NVD for all assets and return a flat list of CVERecords.

        All asset queries run concurrently within the semaphore bounds.
        Exceptions from individual asset queries are caught and logged so
        that a single failed request does not abort the entire scan.

        Parameters
        ----------
        assets : list[SoftwareAsset]
            The inventory to scan. Must not be empty.

        Returns
        -------
        list[CVERecord]
            All CVEs found across all assets.
        """
        if self._session is None:
            raise RuntimeError(
                "NVDClient must be used as an async context manager. "
                "Use: async with NVDClient(...) as client: ..."
            )

        log.info("Starting async NVD scan — %d assets queued.", len(assets))

        tasks = [self._query_asset(asset) for asset in assets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_cves: list[CVERecord] = []
        for asset, result in zip(assets, results):
            if isinstance(result, Exception):
                log.error(
                    "Query failed for %s: %s",
                    asset,
                    result,
                )
            elif isinstance(result, list):
                all_cves.extend(result)

        log.info(
            "NVD scan complete — %d CVE(s) found across %d asset(s).",
            len(all_cves),
            len(assets),
        )
        return all_cves

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    async def _query_asset(self, asset: SoftwareAsset) -> list[CVERecord]:
        """Fetch CVEs for a single asset, respecting rate limits."""
        async with self._semaphore:
            try:
                return await self._fetch_with_retry(asset)
            finally:
                # Always sleep after releasing the semaphore to pace requests
                # even when an exception occurs, preventing rapid error-retry
                # loops that would exhaust the NVD rate limit.
                await asyncio.sleep(self._inter_request_delay)

    async def _fetch_with_retry(
        self, asset: SoftwareAsset
    ) -> list[CVERecord]:
        """Execute the NVD query with exponential backoff retry.

        Retries on:
        - HTTP 429 (rate limited — conservative: we wait and retry)
        - HTTP 503 (NVD maintenance / temporary unavailability)
        - aiohttp.ClientError (network-level failures)

        Does NOT retry on:
        - HTTP 400, 404 — structural problems with the CPE string
        - HTTP 401 — invalid API key
        - HTTP 403 — access denied
        """
        cpe = asset.cpe_string
        params = {
            "cpeName": cpe,
            "resultsPerPage": self._max_results,
            "startIndex": 0,
        }

        for attempt in range(_RETRY_ATTEMPTS):
            try:
                log.info(
                    "Querying NVD: %s %s (CPE: %s, attempt %d/%d)",
                    asset.vendor,
                    asset.product,
                    cpe,
                    attempt + 1,
                    _RETRY_ATTEMPTS,
                )
                assert self._session is not None

                async with self._session.get(
                    _NVD_BASE_URL, params=params
                ) as resp:
                    if resp.status == 200:
                        body = await resp.json(content_type=None)
                        records = self._parse_response(body, asset)
                        log.info(
                            "  -> %d CVE(s) found for %s %s",
                            len(records),
                            asset.product,
                            asset.version,
                        )
                        return records

                    if resp.status in (429, 503):
                        delay = min(
                            _RETRY_BASE_DELAY * (2**attempt),
                            _RETRY_MAX_DELAY,
                        )
                        log.warning(
                            "HTTP %d from NVD for %s — retrying in %.1fs",
                            resp.status,
                            cpe,
                            delay,
                        )
                        await asyncio.sleep(delay)
                        continue

                    # Non-retryable HTTP error
                    body_text = await resp.text()
                    log.warning(
                        "Non-retryable HTTP %d for CPE %s: %s",
                        resp.status,
                        cpe,
                        body_text[:200],
                    )
                    return []

            except aiohttp.ClientError as exc:
                delay = min(
                    _RETRY_BASE_DELAY * (2**attempt),
                    _RETRY_MAX_DELAY,
                )
                log.warning(
                    "Network error querying NVD for %s (attempt %d): %s — "
                    "retrying in %.1fs",
                    cpe,
                    attempt + 1,
                    exc,
                    delay,
                )
                if attempt < _RETRY_ATTEMPTS - 1:
                    await asyncio.sleep(delay)

            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                log.warning(
                    "Response parsing error for CPE %s: %s",
                    cpe,
                    exc,
                )
                return []

        log.error(
            "All %d attempts exhausted for CPE: %s — skipping asset.",
            _RETRY_ATTEMPTS,
            cpe,
        )
        return []

    @staticmethod
    def _parse_response(
        body: dict[str, Any], asset: SoftwareAsset
    ) -> list[CVERecord]:
        """Parse NVD API JSON response into CVERecord objects."""
        vulnerabilities = body.get("vulnerabilities", [])
        records: list[CVERecord] = []

        for vuln in vulnerabilities:
            cve_obj = vuln.get("cve", {})
            cve_id: str = cve_obj.get("id", "N/A")

            # Description — prefer English
            descriptions: list[dict] = cve_obj.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description available.",
            )

            # CVSS with version fallback
            metrics = cve_obj.get("metrics", {})
            score, severity, vector, cvss_ver = _extract_cvss(metrics)

            records.append(
                CVERecord(
                    cve_id=cve_id,
                    description=description,
                    cvss_score=score,
                    cvss_severity=severity,
                    cvss_vector=vector,
                    cvss_version=cvss_ver,
                    published=cve_obj.get("published", "N/A")[:10],
                    last_modified=cve_obj.get("lastModified", "N/A")[:10],
                    asset=asset,
                )
            )

        return records
