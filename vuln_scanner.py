"""
Automated Vulnerability & Asset Scanner
========================================
Queries the National Vulnerability Database (NVD) API v2 for CVEs
matching a simulated Windows software inventory. Generates a
structured PDF risk report with CVSS severity classifications.

Author  : Portfolio Project
Target  : NVD API v2 (https://nvd.nist.gov/developers/vulnerabilities)
License : MIT
"""

from __future__ import annotations

import csv
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import requests
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)-8s]  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_DELAY = 6          # NVD rate-limit: ~10 req/min without API key; 6 s gap
MAX_RESULTS_PER_CPE = 20   # Limit CVEs pulled per software entry
CVSS_THRESHOLD = 0.0       # Minimum CVSS score to include (0 = all)

# NVD API key (optional – raises rate limit significantly).
# Set the environment variable NVD_API_KEY before running.
NVD_API_KEY: str | None = os.environ.get("NVD_API_KEY")

OUTPUT_DIR = Path("reports")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------
@dataclass
class SoftwareAsset:
    """Represents a single installed software record from inventory."""
    host: str
    vendor: str
    product: str
    version: str

    @property
    def cpe_string(self) -> str:
        """Build a CPE 2.3 URI-style string for NVD lookup.

        Format: cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*
        Vendor and product names are lower-cased and spaces replaced with
        underscores to match NVD's normalisation convention.
        """
        vendor = self.vendor.lower().replace(" ", "_").replace("-", "_")
        product = self.product.lower().replace(" ", "_").replace("-", "_")
        version = self.version.lower()
        return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


@dataclass
class CVERecord:
    """Lightweight representation of a CVE returned by the NVD API."""
    cve_id: str
    description: str
    cvss_score: float
    cvss_severity: str
    cvss_vector: str
    published: str
    last_modified: str
    asset: SoftwareAsset


# ---------------------------------------------------------------------------
# Simulated asset inventory
# ---------------------------------------------------------------------------
SIMULATED_INVENTORY: list[dict[str, str]] = [
    # Common enterprise software with known historic CVE exposure.
    # In a production deployment this list would be populated via WMI,
    # Win32_Product, SCCM, or a third-party CMDB.
    {"host": "WS-FINANCE-01",   "vendor": "microsoft",    "product": "internet_explorer", "version": "11.0"},
    {"host": "WS-FINANCE-01",   "vendor": "adobe",        "product": "acrobat_reader",    "version": "2020.001.30005"},
    {"host": "WS-HR-02",        "vendor": "apache",       "product": "log4j",             "version": "2.14.0"},
    {"host": "WS-HR-02",        "vendor": "openssl",      "product": "openssl",           "version": "1.0.1"},
    {"host": "SRV-WEB-01",      "vendor": "apache",       "product": "http_server",       "version": "2.4.49"},
    {"host": "SRV-WEB-01",      "vendor": "php",          "product": "php",               "version": "7.2.0"},
    {"host": "SRV-DB-01",       "vendor": "oracle",       "product": "mysql",             "version": "5.7.35"},
    {"host": "WS-OPS-03",       "vendor": "7-zip",        "product": "7-zip",             "version": "19.00"},
    {"host": "WS-OPS-03",       "vendor": "putty",        "product": "putty",             "version": "0.73"},
    {"host": "SRV-APP-01",      "vendor": "springproject", "product": "spring_framework", "version": "5.3.17"},
]


def load_inventory_from_csv(csv_path: Path) -> list[SoftwareAsset]:
    """Parse a CSV file with columns: host, vendor, product, version."""
    assets: list[SoftwareAsset] = []
    with csv_path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            assets.append(
                SoftwareAsset(
                    host=row["host"].strip(),
                    vendor=row["vendor"].strip(),
                    product=row["product"].strip(),
                    version=row["version"].strip(),
                )
            )
    log.info("Loaded %d assets from %s", len(assets), csv_path)
    return assets


def load_simulated_inventory() -> list[SoftwareAsset]:
    """Return the built-in simulated inventory."""
    assets = [
        SoftwareAsset(
            host=r["host"],
            vendor=r["vendor"],
            product=r["product"],
            version=r["version"],
        )
        for r in SIMULATED_INVENTORY
    ]
    log.info("Loaded %d assets from built-in simulated inventory.", len(assets))
    return assets


# ---------------------------------------------------------------------------
# NVD API client
# ---------------------------------------------------------------------------
def _build_headers() -> dict[str, str]:
    headers = {"Accept": "application/json"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    return headers


def query_nvd_for_cpe(asset: SoftwareAsset) -> list[CVERecord]:
    """Query NVD API v2 for CVEs matching the asset's CPE string.

    Returns a (possibly empty) list of CVERecord objects.
    """
    cpe = asset.cpe_string
    params: dict[str, Any] = {
        "cpeName": cpe,
        "resultsPerPage": MAX_RESULTS_PER_CPE,
        "startIndex": 0,
    }

    log.info("Querying NVD for: %s  (CPE: %s)", asset.product, cpe)

    try:
        resp = requests.get(
            NVD_BASE_URL,
            params=params,
            headers=_build_headers(),
            timeout=30,
        )
        resp.raise_for_status()
    except requests.exceptions.HTTPError as exc:
        log.warning("HTTP error querying NVD for %s: %s", cpe, exc)
        return []
    except requests.exceptions.RequestException as exc:
        log.warning("Network error querying NVD for %s: %s", cpe, exc)
        return []

    try:
        data = resp.json()
    except json.JSONDecodeError:
        log.warning("Invalid JSON response for CPE: %s", cpe)
        return []

    vulnerabilities = data.get("vulnerabilities", [])
    records: list[CVERecord] = []

    for vuln in vulnerabilities:
        cve_obj = vuln.get("cve", {})
        cve_id = cve_obj.get("id", "N/A")

        # Description (prefer English)
        descriptions = cve_obj.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available.",
        )

        # CVSS score – prefer v3.1, fall back to v3.0, then v2.0
        metrics = cve_obj.get("metrics", {})
        cvss_score, cvss_severity, cvss_vector = _extract_cvss(metrics)

        if cvss_score < CVSS_THRESHOLD:
            continue

        published = cve_obj.get("published", "N/A")[:10]
        last_modified = cve_obj.get("lastModified", "N/A")[:10]

        records.append(
            CVERecord(
                cve_id=cve_id,
                description=description,
                cvss_score=cvss_score,
                cvss_severity=cvss_severity,
                cvss_vector=cvss_vector,
                published=published,
                last_modified=last_modified,
                asset=asset,
            )
        )

    log.info(
        "  -> %d CVE(s) found for %s %s",
        len(records),
        asset.product,
        asset.version,
    )
    return records


def _extract_cvss(metrics: dict) -> tuple[float, str, str]:
    """Extract the most current available CVSS data from the metrics block."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if key in metrics:
            m = metrics[key][0].get("cvssData", {})
            return (
                float(m.get("baseScore", 0.0)),
                m.get("baseSeverity", "UNKNOWN"),
                m.get("vectorString", "N/A"),
            )
    if "cvssMetricV2" in metrics:
        m = metrics["cvssMetricV2"][0].get("cvssData", {})
        severity = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")
        return (
            float(m.get("baseScore", 0.0)),
            severity,
            m.get("vectorString", "N/A"),
        )
    return 0.0, "UNKNOWN", "N/A"


# ---------------------------------------------------------------------------
# Scanner orchestration
# ---------------------------------------------------------------------------
def run_scan(assets: list[SoftwareAsset]) -> list[CVERecord]:
    """Iterate over all assets, query NVD, and return consolidated CVE list."""
    all_cves: list[CVERecord] = []

    for idx, asset in enumerate(assets):
        cves = query_nvd_for_cpe(asset)
        all_cves.extend(cves)

        # Respect NVD rate limits between requests
        if idx < len(assets) - 1:
            log.info("Rate-limit delay: %d seconds...", REQUEST_DELAY)
            time.sleep(REQUEST_DELAY)

    log.info("Scan complete. Total CVEs discovered: %d", len(all_cves))
    return all_cves


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------
SEVERITY_COLOR_MAP = {
    "CRITICAL": colors.HexColor("#C0392B"),
    "HIGH":     colors.HexColor("#E67E22"),
    "MEDIUM":   colors.HexColor("#F1C40F"),
    "LOW":      colors.HexColor("#27AE60"),
    "UNKNOWN":  colors.HexColor("#95A5A6"),
}


def severity_sort_key(rec: CVERecord) -> tuple[int, float]:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    return (order.get(rec.cvss_severity.upper(), 5), -rec.cvss_score)


# ---------------------------------------------------------------------------
# PDF report generation
# ---------------------------------------------------------------------------
def generate_pdf_report(cves: list[CVERecord], assets: list[SoftwareAsset]) -> Path:
    """Build a structured PDF risk report and return the output path."""
    OUTPUT_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = OUTPUT_DIR / f"VulnScan_Report_{timestamp}.pdf"

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
    )

    styles = getSampleStyleSheet()
    story: list = []

    # ---- Custom styles ---------------------------------------------------- #
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=20,
        textColor=colors.HexColor("#1A252F"),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#5D6D7E"),
        spaceAfter=2,
    )
    section_header_style = ParagraphStyle(
        "SectionHeader",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#1A252F"),
        spaceBefore=10,
        spaceAfter=4,
        borderPad=2,
    )
    body_style = ParagraphStyle(
        "BodyText",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#2C3E50"),
    )
    small_style = ParagraphStyle(
        "SmallText",
        parent=styles["Normal"],
        fontSize=7,
        leading=10,
        textColor=colors.HexColor("#5D6D7E"),
    )

    # ---- Header block ----------------------------------------------------- #
    story.append(Paragraph("Automated Vulnerability Scan Report", title_style))
    story.append(
        Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  "
            f"Assets Scanned: {len(assets)}  |  "
            f"Total CVEs Identified: {len(cves)}",
            subtitle_style,
        )
    )
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1A252F")))
    story.append(Spacer(1, 6 * mm))

    # ---- Executive summary ------------------------------------------------ #
    story.append(Paragraph("Executive Summary", section_header_style))

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for cve in cves:
        key = cve.cvss_severity.upper()
        severity_counts[key] = severity_counts.get(key, 0) + 1

    summary_data = [
        ["Severity", "Count", "Risk Level"],
        ["CRITICAL", str(severity_counts["CRITICAL"]), "Immediate remediation required"],
        ["HIGH",     str(severity_counts["HIGH"]),     "Remediate within 30 days"],
        ["MEDIUM",   str(severity_counts["MEDIUM"]),   "Remediate within 90 days"],
        ["LOW",      str(severity_counts["LOW"]),      "Monitor and schedule patch"],
        ["UNKNOWN",  str(severity_counts["UNKNOWN"]),  "Manual assessment required"],
    ]

    summary_table = Table(
        summary_data,
        colWidths=[45 * mm, 25 * mm, 95 * mm],
    )
    summary_table.setStyle(
        TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#1A252F")),
            ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, 0), 9),
            ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#F2F3F4"), colors.white]),
            ("FONTSIZE",    (0, 1), (-1, -1), 8),
            ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#BDC3C7")),
            ("TOPPADDING",  (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            # Severity cell colours
            ("BACKGROUND",  (0, 1), (0, 1), colors.HexColor("#C0392B")),
            ("TEXTCOLOR",   (0, 1), (0, 1), colors.white),
            ("BACKGROUND",  (0, 2), (0, 2), colors.HexColor("#E67E22")),
            ("TEXTCOLOR",   (0, 2), (0, 2), colors.white),
            ("BACKGROUND",  (0, 3), (0, 3), colors.HexColor("#D4AC0D")),
            ("TEXTCOLOR",   (0, 3), (0, 3), colors.HexColor("#1A252F")),
            ("BACKGROUND",  (0, 4), (0, 4), colors.HexColor("#27AE60")),
            ("TEXTCOLOR",   (0, 4), (0, 4), colors.white),
        ])
    )
    story.append(summary_table)
    story.append(Spacer(1, 6 * mm))

    # ---- Asset inventory table -------------------------------------------- #
    story.append(Paragraph("Scanned Asset Inventory", section_header_style))

    inv_data = [["Host", "Vendor", "Product", "Version", "CPE"]]
    for a in assets:
        inv_data.append([
            Paragraph(a.host, small_style),
            Paragraph(a.vendor, small_style),
            Paragraph(a.product, small_style),
            Paragraph(a.version, small_style),
            Paragraph(a.cpe_string, small_style),
        ])

    inv_table = Table(inv_data, colWidths=[32 * mm, 22 * mm, 32 * mm, 22 * mm, 62 * mm])
    inv_table.setStyle(
        TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
            ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
            ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",     (0, 0), (-1, 0), 8),
            ("ALIGN",        (0, 0), (-1, 0), "CENTER"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#F8F9F9"), colors.white]),
            ("GRID",         (0, 0), (-1, -1), 0.4, colors.HexColor("#BDC3C7")),
            ("TOPPADDING",   (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ])
    )
    story.append(inv_table)
    story.append(Spacer(1, 6 * mm))

    # ---- CVE detail table ------------------------------------------------- #
    story.append(Paragraph("Identified Vulnerabilities (Sorted by Severity)", section_header_style))

    if not cves:
        story.append(
            Paragraph(
                "No CVEs were returned by the NVD API for the queried CPE strings. "
                "This may indicate that NVD has no matching records for the exact CPE "
                "or that the software is not indexed under the queried vendor/product "
                "naming convention. Manual verification is recommended.",
                body_style,
            )
        )
    else:
        sorted_cves = sorted(cves, key=severity_sort_key)

        cve_data = [["CVE ID", "Host", "Product", "Ver.", "CVSS", "Severity", "Published", "Description"]]
        for rec in sorted_cves:
            sev = rec.cvss_severity.upper()
            sev_color = SEVERITY_COLOR_MAP.get(sev, colors.grey)
            cve_data.append([
                Paragraph(f"<b>{rec.cve_id}</b>", small_style),
                Paragraph(rec.asset.host, small_style),
                Paragraph(rec.asset.product, small_style),
                Paragraph(rec.asset.version, small_style),
                Paragraph(str(rec.cvss_score), small_style),
                Paragraph(f"<b>{sev}</b>", small_style),
                Paragraph(rec.published, small_style),
                Paragraph(rec.description[:220] + ("..." if len(rec.description) > 220 else ""), small_style),
            ])

        cve_table = Table(
            cve_data,
            colWidths=[25 * mm, 22 * mm, 22 * mm, 12 * mm, 10 * mm, 17 * mm, 18 * mm, 44 * mm],
            repeatRows=1,
        )

        # Build per-row severity colouring
        row_styles = [
            ("BACKGROUND",   (0, 0), (-1, 0), colors.HexColor("#1A252F")),
            ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
            ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",     (0, 0), (-1, 0), 7),
            ("ALIGN",        (0, 0), (-1, 0), "CENTER"),
            ("VALIGN",       (0, 0), (-1, -1), "TOP"),
            ("GRID",         (0, 0), (-1, -1), 0.3, colors.HexColor("#BDC3C7")),
            ("TOPPADDING",   (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#F8F9F9"), colors.white]),
        ]

        sorted_sevs = [rec.cvss_severity.upper() for rec in sorted_cves]
        for i, sev in enumerate(sorted_sevs, start=1):
            c = SEVERITY_COLOR_MAP.get(sev)
            if c:
                row_styles.append(("BACKGROUND", (5, i), (5, i), c))
                if sev in ("CRITICAL", "HIGH", "UNKNOWN", "LOW"):
                    row_styles.append(("TEXTCOLOR", (5, i), (5, i), colors.white))
                else:
                    row_styles.append(("TEXTCOLOR", (5, i), (5, i), colors.HexColor("#1A252F")))

        cve_table.setStyle(TableStyle(row_styles))
        story.append(cve_table)

    story.append(Spacer(1, 6 * mm))

    # ---- Remediation guidance --------------------------------------------- #
    story.append(Paragraph("Remediation Priority Guidelines", section_header_style))
    guidance = (
        "<b>CRITICAL (CVSS 9.0-10.0):</b> Apply vendor patch or implement compensating controls "
        "immediately. Escalate to security team. Isolate affected systems if exploitation is confirmed.<br/><br/>"
        "<b>HIGH (CVSS 7.0-8.9):</b> Schedule patching within the current change-management cycle (target: 30 days). "
        "Monitor for active exploitation indicators via threat intelligence feeds.<br/><br/>"
        "<b>MEDIUM (CVSS 4.0-6.9):</b> Include in the next quarterly patch cycle (target: 90 days). "
        "Assess compensating controls where patching is not immediately feasible.<br/><br/>"
        "<b>LOW (CVSS 0.1-3.9):</b> Schedule during routine maintenance windows. "
        "Document risk acceptance if deferral exceeds 180 days.<br/><br/>"
        "<b>Data Source:</b> National Vulnerability Database (NVD) — NIST. "
        "CVE severity scores are based on the Common Vulnerability Scoring System (CVSS). "
        "This report is auto-generated and must be reviewed by a qualified security professional "
        "before remediation actions are initiated."
    )
    story.append(Paragraph(guidance, body_style))

    # ---- Footer ----------------------------------------------------------- #
    story.append(Spacer(1, 8 * mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#BDC3C7")))
    story.append(
        Paragraph(
            f"CONFIDENTIAL — Automated Vulnerability Scan Report  |  "
            f"Generated by NVD-VulnScanner  |  {datetime.now().strftime('%Y-%m-%d')}",
            small_style,
        )
    )

    doc.build(story)
    log.info("PDF report saved: %s", output_path)
    return output_path


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    log.info("=" * 60)
    log.info("NVD Automated Vulnerability & Asset Scanner")
    log.info("=" * 60)

    # Determine inventory source
    csv_path = Path("assets.csv")
    if csv_path.exists():
        log.info("External inventory file detected: %s", csv_path)
        assets = load_inventory_from_csv(csv_path)
    else:
        log.info("No assets.csv found — using built-in simulated inventory.")
        assets = load_simulated_inventory()

    if not assets:
        log.error("No assets to scan. Exiting.")
        sys.exit(1)

    if not NVD_API_KEY:
        log.warning(
            "NVD_API_KEY environment variable not set. "
            "Operating under public rate limit (~10 req/min). "
            "Set NVD_API_KEY for higher throughput."
        )

    # Run the scan
    cves = run_scan(assets)

    # Generate report
    report_path = generate_pdf_report(cves, assets)

    log.info("=" * 60)
    log.info("Report generated: %s", report_path.resolve())
    log.info("=" * 60)


if __name__ == "__main__":
    main()
