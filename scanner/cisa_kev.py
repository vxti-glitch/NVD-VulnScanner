"""CISA KEV catalog lookup for candidate-correlation context.

BOD 22-01 is binding on U.S. federal civilian executive branch agencies.
Other organizations can use KEV as prioritization guidance under their own
authorized policies. Every matched record retains the entry's actual dueDate.

Catalog source:
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Known ransomware association:
  CISA marks KEV entries where the vulnerability has been linked to
  known ransomware campaigns ("knownRansomwareCampaignUse": "Known").
  This is surfaced in the report as an additional escalation indicator.
"""

from __future__ import annotations

import logging
from typing import Any

import aiohttp

from .models import CVERecord, KEVEntry

log = logging.getLogger(__name__)

_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
_KEV_TIMEOUT = 20  # seconds


class FixtureDataError(ValueError):
    """Raised when a recorded API fixture is malformed or outside its review window."""


# ---------------------------------------------------------------------------
# KEV catalog container
# ---------------------------------------------------------------------------
class KEVCatalog:
    """In-memory index of the CISA KEV catalog.

    Keyed by CVE ID (e.g. "CVE-2021-44228") for O(1) lookup.
    """

    def __init__(self, entries: dict[str, KEVEntry], catalog_version: str) -> None:
        self._entries = entries
        self.catalog_version = catalog_version
        self.total_entries = len(entries)

    def lookup(self, cve_id: str) -> KEVEntry | None:
        """Return a KEVEntry if the CVE ID is in the catalog, else None."""
        return self._entries.get(cve_id)

    def enrich(self, cves: list[CVERecord]) -> tuple[list[CVERecord], int]:
        """Cross-reference a list of CVERecords against the KEV catalog.

        Mutates each matching CVERecord in-place by setting its `kev_entry`
        field. Returns the same list and a count of matched records.

        Parameters
        ----------
        cves : list[CVERecord]
            CVE records from the NVD scan, prior to KEV enrichment.

        Returns
        -------
        tuple[list[CVERecord], int]
            (enriched_cves, kev_match_count)
        """
        matched = 0
        for rec in cves:
            entry = self.lookup(rec.cve_id)
            if entry is not None:
                rec.kev_entry = entry
                matched += 1
                log.warning(
                    "KEV MATCH: %s is in CISA Known Exploited Vulnerabilities "
                    "catalog (ransomware: %s, due: %s)",
                    rec.cve_id,
                    "YES" if entry.known_ransomware else "NO",
                    entry.due_date,
                )
        return cves, matched

    @classmethod
    def from_payload(cls, body: dict[str, Any]) -> "KEVCatalog":
        """Validate a recorded/live KEV payload before constructing a catalog."""
        if not isinstance(body, dict):
            raise FixtureDataError("KEV payload must be an object")
        raw = body.get("vulnerabilities")
        version = body.get("catalogVersion")
        if not isinstance(raw, list) or not isinstance(version, str) or not version.strip():
            raise FixtureDataError("KEV payload is missing catalogVersion or vulnerabilities")
        entries = cls._parse(raw)
        if raw and not entries:
            raise FixtureDataError("KEV payload contains no usable CVE records")
        return cls(entries=entries, catalog_version=version)

    @classmethod
    async def fetch(
        cls,
        session: aiohttp.ClientSession,
        timeout: int = _KEV_TIMEOUT,
    ) -> "KEVCatalog":
        """Fetch and parse the CISA KEV JSON catalog.

        Falls back to an empty catalog on any error so that a KEV outage
        does not abort the entire scan — CVE data from NVD is still valid
        without KEV enrichment.

        Parameters
        ----------
        session : aiohttp.ClientSession
            Shared aiohttp session (passed in to avoid creating a second one).
        timeout : int
            Request timeout in seconds.

        Returns
        -------
        KEVCatalog
            Populated catalog, or an empty catalog on fetch failure.
        """
        try:
            log.info("Fetching CISA KEV catalog from %s", _KEV_URL)
            request_timeout = aiohttp.ClientTimeout(total=timeout)

            async with session.get(_KEV_URL, timeout=request_timeout) as resp:
                if resp.status != 200:
                    log.warning(
                        "CISA KEV catalog returned HTTP %d — "
                        "proceeding without KEV enrichment.",
                        resp.status,
                    )
                    return cls._empty()

                body: dict[str, Any] = await resp.json(content_type=None)

        except aiohttp.ClientError as exc:
            log.warning(
                "Network error fetching CISA KEV catalog: %s — "
                "proceeding without KEV enrichment.",
                exc,
            )
            return cls._empty()

        except Exception as exc:  # noqa: BLE001
            log.warning(
                "Unexpected error fetching CISA KEV catalog: %s — "
                "proceeding without KEV enrichment.",
                exc,
            )
            return cls._empty()

        try:
            catalog = cls.from_payload(body)
        except FixtureDataError as exc:
            log.warning("Malformed CISA KEV catalog: %s — KEV status is unknown.", exc)
            return cls._empty()

        log.info(
            "CISA KEV catalog loaded: %d entries (version %s).",
            catalog.total_entries,
            catalog.catalog_version,
        )
        return catalog

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _parse(raw: list[dict[str, Any]]) -> dict[str, KEVEntry]:
        """Convert raw JSON vulnerability list to a CVE-ID-keyed dict."""
        result: dict[str, KEVEntry] = {}
        for item in raw:
            cve_id = item.get("cveID", "").strip()
            if not cve_id:
                continue
            ransomware_flag = (
                item.get("knownRansomwareCampaignUse", "").strip().lower() == "known"
            )
            result[cve_id] = KEVEntry(
                cve_id=cve_id,
                vulnerability_name=item.get("vulnerabilityName", "N/A"),
                vendor_project=item.get("vendorProject", "N/A"),
                product=item.get("product", "N/A"),
                date_added=item.get("dateAdded", "N/A"),
                due_date=item.get("dueDate", "N/A"),
                known_ransomware=ransomware_flag,
                required_action=item.get("requiredAction", "N/A"),
            )
        return result

    @classmethod
    def _empty(cls) -> "KEVCatalog":
        return cls(entries={}, catalog_version="unavailable")
