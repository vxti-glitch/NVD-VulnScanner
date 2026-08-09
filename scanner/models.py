"""
scanner.models
==============
Core domain dataclasses shared across all scanner modules.

Design notes (Backend Architect)
---------------------------------
- Dataclasses are frozen where mutation is not required so they are safe
  to cache and pass across async task boundaries without defensive copying.
- KEVEntry is kept separate from CVERecord so the cross-reference step is
  an explicit enrichment pass, not an implicit side-effect of the NVD fetch.
- SLA logic lives on CVERecord so report.py stays free of business-rule
  conditionals — the model owns its own priority semantics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# CISA KEV entry
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class KEVEntry:
    """A single record from the CISA Known Exploited Vulnerabilities catalog."""

    cve_id: str
    vulnerability_name: str
    vendor_project: str
    product: str
    date_added: str          # ISO 8601 date string
    due_date: str            # CISA patch-by date (BOD 22-01)
    known_ransomware: bool   # True if linked to confirmed ransomware campaigns
    required_action: str


# ---------------------------------------------------------------------------
# Software asset
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class SoftwareAsset:
    """Represents a single installed software record from an asset inventory.

    In production this is populated from WMI (Win32_Product), SCCM software
    inventory, or a CMDB export. For this project the source is either the
    built-in simulated inventory or an operator-supplied CSV.
    """

    host: str
    vendor: str
    product: str
    version: str

    @property
    def cpe_string(self) -> str:
        """Construct a CPE 2.3 formatted string for NVD API lookup.

        Normalisation rules applied:
        - All fields lowercased
        - Spaces and hyphens replaced with underscores
        - Version string passed as-is (already normalised by NVD convention)

        Example output:
            cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*
        """
        def _normalise(s: str) -> str:
            return s.lower().replace(" ", "_").replace("-", "_")

        return (
            f"cpe:2.3:a:{_normalise(self.vendor)}:"
            f"{_normalise(self.product)}:{self.version}:*:*:*:*:*:*:*"
        )

    def __str__(self) -> str:
        return f"{self.host} / {self.vendor} {self.product} {self.version}"


# ---------------------------------------------------------------------------
# CVE record
# ---------------------------------------------------------------------------
@dataclass
class CVERecord:
    """A CVE returned by the NVD API, optionally enriched with KEV data.

    The `kev_entry` field is None until the KEV cross-reference pass runs.
    This is intentional — the NVD fetch and KEV lookup are independent I/O
    operations that happen at different points in the pipeline.
    """

    cve_id: str
    description: str
    cvss_score: float
    cvss_severity: str       # CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
    cvss_vector: str
    cvss_version: str        # 3.1 | 3.0 | 2.0 | UNKNOWN
    published: str           # ISO 8601 date (truncated to date only)
    last_modified: str
    asset: SoftwareAsset
    kev_entry: Optional[KEVEntry] = field(default=None)

    # ------------------------------------------------------------------
    # Derived properties
    # ------------------------------------------------------------------

    @property
    def is_kev(self) -> bool:
        """True if this CVE appears in the CISA KEV catalog."""
        return self.kev_entry is not None

    @property
    def sla_days(self) -> int:
        """Patch SLA in calendar days.

        Priority ordering:
        1. CISA BOD 22-01 KEV items → 14 days (federal mandate baseline)
        2. CVSS Critical (non-KEV) → 30 days
        3. CVSS High → 60 days
        4. CVSS Medium → 90 days
        5. CVSS Low / Unknown → 180 days
        """
        if self.is_kev:
            return 14
        return {
            "CRITICAL": 30,
            "HIGH": 60,
            "MEDIUM": 90,
            "LOW": 180,
        }.get(self.cvss_severity.upper(), 180)

    @property
    def severity_rank(self) -> int:
        """Numeric sort key — lower = higher priority."""
        # KEV items sort above same-severity non-KEV items
        base = {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 4, "LOW": 6, "UNKNOWN": 8}.get(
            self.cvss_severity.upper(), 8
        )
        return base if self.is_kev else base + 1

    def __str__(self) -> str:
        kev_tag = " [KEV]" if self.is_kev else ""
        return (
            f"{self.cve_id}{kev_tag} | {self.cvss_severity} "
            f"({self.cvss_score}) | {self.asset}"
        )
