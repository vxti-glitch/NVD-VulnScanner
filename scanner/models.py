"""Domain models for the inventory-to-NVD/KEV correlation helper."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

_CPE_PREFIX = "cpe:2.3:"


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
    """One software inventory record plus its reviewable CPE mapping state."""

    host: str
    vendor: str
    product: str
    version: str
    reviewed_cpe: str | None = None
    mapping_source: str | None = None
    candidate_cpes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.reviewed_cpe and not self.reviewed_cpe.startswith(_CPE_PREFIX):
            raise ValueError("reviewed_cpe must be a CPE 2.3 name")
        if self.reviewed_cpe and self.reviewed_cpe.count(":") != 12:
            raise ValueError("reviewed_cpe must contain all CPE 2.3 components")
        if self.reviewed_cpe and not self.mapping_source:
            raise ValueError("mapping_source is required with reviewed_cpe")

    @property
    def cpe_string(self) -> str:
        """Return only an explicitly reviewed CPE; never synthesize one."""
        return self.reviewed_cpe or "unresolved"

    @property
    def mapping_status(self) -> str:
        if self.reviewed_cpe:
            return "matched"
        if len(self.candidate_cpes) > 1:
            return "ambiguous"
        return "unresolved"

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

    def target_days(self, organizational_targets: dict[str, int]) -> int | None:
        """Return an optional sample organizational target for non-KEV items."""
        if self.is_kev:
            return None
        return organizational_targets.get(self.cvss_severity.upper())

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
