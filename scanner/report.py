"""
scanner.report
==============
PDF risk report generator using ReportLab.

Report structure
----------------
1. Title block — timestamp, scan statistics, KEV catalog version
2. Actively Exploited Vulnerabilities — KEV-matched CVEs only (priority section)
3. Executive Summary — severity distribution table with SLA column
4. Scanned Asset Inventory — all hosts with CPE strings
5. Full Vulnerability Detail — all CVEs sorted by severity_rank
6. Remediation SLA Reference — CISA BOD 22-01 + CVSS-based guidance
7. Footer — classification marking and generation timestamp

Design notes (Penetration Tester + Backend Architect)
------------------------------------------------------
- KEV-matched CVEs appear in a dedicated top section labelled
  "Actively Exploited" so they cannot be buried in a long CVE table.
- Ransomware-associated KEV entries are additionally flagged.
- SLA column on each CVE row enforces CISA BOD 22-01 timelines,
  giving IT operations a concrete patch deadline, not just a severity.
- Zero-CVE case is handled gracefully — the report still renders with
  an explicit "No vulnerabilities identified" notice.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Sequence

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

from .models import CVERecord, SoftwareAsset

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Output directory
# ---------------------------------------------------------------------------
OUTPUT_DIR = Path("reports")

# ---------------------------------------------------------------------------
# Colour palette (consistent corporate palette throughout)
# ---------------------------------------------------------------------------
_C_NAVY = colors.HexColor("#1A252F")
_C_SLATE = colors.HexColor("#2C3E50")
_C_MID = colors.HexColor("#5D6D7E")
_C_RULE = colors.HexColor("#BDC3C7")
_C_ROW_ALT = colors.HexColor("#F2F3F4")
_C_ROW_EVEN = colors.white

# Severity colours
_C_CRITICAL = colors.HexColor("#C0392B")
_C_HIGH = colors.HexColor("#E67E22")
_C_MEDIUM = colors.HexColor("#D4AC0D")
_C_LOW = colors.HexColor("#27AE60")
_C_UNKNOWN = colors.HexColor("#95A5A6")
_C_KEV = colors.HexColor("#6C3483")  # Purple — KEV / actively exploited

SEVERITY_COLORS: dict[str, colors.HexColor] = {
    "CRITICAL": _C_CRITICAL,
    "HIGH": _C_HIGH,
    "MEDIUM": _C_MEDIUM,
    "LOW": _C_LOW,
    "UNKNOWN": _C_UNKNOWN,
}


# ---------------------------------------------------------------------------
# Style factory
# ---------------------------------------------------------------------------
def _build_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()

    return {
        "title": ParagraphStyle(
            "RptTitle",
            parent=base["Title"],
            fontSize=20,
            textColor=_C_NAVY,
            spaceAfter=3,
        ),
        "subtitle": ParagraphStyle(
            "RptSubtitle",
            parent=base["Normal"],
            fontSize=9,
            textColor=_C_MID,
            spaceAfter=2,
        ),
        "section": ParagraphStyle(
            "RptSection",
            parent=base["Heading2"],
            fontSize=12,
            textColor=_C_NAVY,
            spaceBefore=8,
            spaceAfter=4,
        ),
        "kev_section": ParagraphStyle(
            "RptKEVSection",
            parent=base["Heading2"],
            fontSize=12,
            textColor=_C_KEV,
            spaceBefore=8,
            spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "RptBody",
            parent=base["Normal"],
            fontSize=8,
            leading=12,
            textColor=_C_SLATE,
        ),
        "small": ParagraphStyle(
            "RptSmall",
            parent=base["Normal"],
            fontSize=7,
            leading=10,
            textColor=_C_SLATE,
        ),
        "small_kev": ParagraphStyle(
            "RptSmallKEV",
            parent=base["Normal"],
            fontSize=7,
            leading=10,
            textColor=_C_KEV,
        ),
        "footer": ParagraphStyle(
            "RptFooter",
            parent=base["Normal"],
            fontSize=6.5,
            textColor=_C_MID,
        ),
    }


# ---------------------------------------------------------------------------
# Table style helpers
# ---------------------------------------------------------------------------
def _header_table_style(
    row_colors: list[tuple] | None = None,
) -> TableStyle:
    """Standard header + alternating row table style."""
    commands = [
        ("BACKGROUND",    (0, 0), (-1, 0), _C_NAVY),
        ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 8),
        ("ALIGN",         (0, 0), (-1, 0), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [_C_ROW_ALT, _C_ROW_EVEN]),
        ("FONTSIZE",      (0, 1), (-1, -1), 7),
        ("GRID",          (0, 0), (-1, -1), 0.3, _C_RULE),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
    ]
    if row_colors:
        commands.extend(row_colors)
    return TableStyle(commands)


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------
def _build_kev_section(
    kev_cves: list[CVERecord],
    styles: dict[str, ParagraphStyle],
    story: list,
) -> None:
    """Render the 'Actively Exploited' KEV-only section."""
    story.append(Paragraph("Actively Exploited Vulnerabilities (CISA KEV)", styles["kev_section"]))
    story.append(
        Paragraph(
            "The following vulnerabilities have confirmed real-world exploitation evidence "
            "and are listed in the CISA Known Exploited Vulnerabilities (KEV) catalog. "
            "CISA Binding Operational Directive 22-01 mandates patching within <b>14 days</b>. "
            "Industry best practice applies the same timeline regardless of regulatory mandate.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 3 * mm))

    if not kev_cves:
        story.append(
            Paragraph(
                "No KEV-listed vulnerabilities were found in the scanned inventory.",
                styles["body"],
            )
        )
        return

    headers = ["CVE ID", "Host", "Product", "CVSS", "Ransomware", "CISA Due Date", "Required Action"]
    rows = [headers]
    for rec in kev_cves:
        kev = rec.kev_entry
        assert kev is not None
        ransomware_text = "YES — LINKED" if kev.known_ransomware else "No known link"
        rows.append([
            Paragraph(f"<b>{rec.cve_id}</b>", styles["small_kev"]),
            Paragraph(rec.asset.host, styles["small"]),
            Paragraph(rec.asset.product, styles["small"]),
            Paragraph(str(rec.cvss_score), styles["small"]),
            Paragraph(ransomware_text, styles["small"]),
            Paragraph(kev.due_date, styles["small"]),
            Paragraph(kev.required_action[:120], styles["small"]),
        ])

    col_widths = [27 * mm, 22 * mm, 22 * mm, 12 * mm, 24 * mm, 22 * mm, 42 * mm]
    row_style_commands = [
        ("BACKGROUND", (0, 0), (-1, 0), _C_KEV),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, 0), 8),
    ]
    # Highlight ransomware-linked rows
    for i, rec in enumerate(kev_cves, start=1):
        if rec.kev_entry and rec.kev_entry.known_ransomware:
            row_style_commands.append(
                ("BACKGROUND", (4, i), (4, i), colors.HexColor("#7B241C"))
            )
            row_style_commands.append(
                ("TEXTCOLOR", (4, i), (4, i), colors.white)
            )

    table = Table(rows, colWidths=col_widths, repeatRows=1)
    table.setStyle(_header_table_style(row_style_commands))
    story.append(table)


def _build_summary_section(
    cves: list[CVERecord],
    kev_count: int,
    styles: dict[str, ParagraphStyle],
    story: list,
) -> None:
    """Render the executive summary severity distribution table."""
    story.append(Paragraph("Executive Summary", styles["section"]))

    counts: dict[str, int] = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0
    }
    for c in cves:
        key = c.cvss_severity.upper()
        counts[key] = counts.get(key, 0) + 1

    sla_map = {"CRITICAL": "30 days", "HIGH": "60 days", "MEDIUM": "90 days",
               "LOW": "180 days", "UNKNOWN": "Manual review"}
    color_map = {
        "CRITICAL": _C_CRITICAL, "HIGH": _C_HIGH, "MEDIUM": _C_MEDIUM,
        "LOW": _C_LOW, "UNKNOWN": _C_UNKNOWN,
    }

    headers = ["Severity", "Count", "Patch SLA (non-KEV)", "Risk Guidance"]
    guidance = {
        "CRITICAL": "Immediate action — escalate to security team",
        "HIGH": "Patch within current change-management cycle",
        "MEDIUM": "Include in next quarterly patch cycle",
        "LOW": "Schedule during next maintenance window",
        "UNKNOWN": "Manual CVSS assessment required",
    }

    rows = [headers]
    row_style_commands = []
    for i, (sev, label_color) in enumerate(color_map.items(), start=1):
        rows.append([sev, str(counts[sev]), sla_map[sev], guidance[sev]])
        row_style_commands += [
            ("BACKGROUND", (0, i), (0, i), label_color),
            ("TEXTCOLOR",  (0, i), (0, i),
             colors.white if sev not in ("MEDIUM",) else _C_NAVY),
            ("FONTNAME",   (0, i), (0, i), "Helvetica-Bold"),
        ]

    # KEV summary row
    rows.append([
        Paragraph("<b>KEV (Actively Exploited)</b>", styles["small"]),
        str(kev_count),
        "14 days (CISA BOD 22-01)",
        "Patch immediately — confirmed real-world exploitation",
    ])
    kev_row_idx = len(rows) - 1
    row_style_commands += [
        ("BACKGROUND", (0, kev_row_idx), (0, kev_row_idx), _C_KEV),
        ("TEXTCOLOR",  (0, kev_row_idx), (0, kev_row_idx), colors.white),
        ("FONTNAME",   (0, kev_row_idx), (0, kev_row_idx), "Helvetica-Bold"),
    ]

    table = Table(rows, colWidths=[30 * mm, 18 * mm, 45 * mm, 77 * mm])
    table.setStyle(_header_table_style(row_style_commands))
    story.append(table)


def _build_inventory_section(
    assets: Sequence[SoftwareAsset],
    styles: dict[str, ParagraphStyle],
    story: list,
) -> None:
    """Render the scanned asset inventory table."""
    story.append(Paragraph("Scanned Asset Inventory", styles["section"]))

    headers = ["Host", "Vendor", "Product", "Version", "CPE String"]
    rows = [headers]
    for a in assets:
        rows.append([
            Paragraph(a.host, styles["small"]),
            Paragraph(a.vendor, styles["small"]),
            Paragraph(a.product, styles["small"]),
            Paragraph(a.version, styles["small"]),
            Paragraph(a.cpe_string, styles["small"]),
        ])

    table = Table(
        rows, colWidths=[32 * mm, 22 * mm, 30 * mm, 22 * mm, 64 * mm],
        repeatRows=1,
    )
    table.setStyle(_header_table_style([
        ("BACKGROUND", (0, 0), (-1, 0), _C_SLATE),
    ]))
    story.append(table)


def _build_cve_detail_section(
    cves: list[CVERecord],
    styles: dict[str, ParagraphStyle],
    story: list,
) -> None:
    """Render the full CVE detail table sorted by severity_rank."""
    story.append(
        Paragraph("Full Vulnerability Detail (Sorted by Priority)", styles["section"])
    )

    if not cves:
        story.append(
            Paragraph(
                "No vulnerabilities were returned by the NVD API for the queried CPE strings. "
                "This indicates that NVD has no matching records for the exact CPE naming used. "
                "Manual verification via the NVD CPE dictionary is recommended.",
                styles["body"],
            )
        )
        return

    sorted_cves = sorted(cves, key=lambda r: (r.severity_rank, -r.cvss_score))

    headers = [
        "CVE ID", "Host", "Product", "Ver.", "CVSS", "Severity",
        "KEV", "SLA", "Published", "Description",
    ]
    rows = [headers]
    row_style_commands = []

    for i, rec in enumerate(sorted_cves, start=1):
        sev = rec.cvss_severity.upper()
        kev_tag = Paragraph(
            "<b>YES</b>" if rec.is_kev else "No",
            styles["small_kev"] if rec.is_kev else styles["small"],
        )
        rows.append([
            Paragraph(f"<b>{rec.cve_id}</b>", styles["small"]),
            Paragraph(rec.asset.host, styles["small"]),
            Paragraph(rec.asset.product, styles["small"]),
            Paragraph(rec.asset.version, styles["small"]),
            Paragraph(str(rec.cvss_score), styles["small"]),
            Paragraph(f"<b>{sev}</b>", styles["small"]),
            kev_tag,
            Paragraph(f"{rec.sla_days}d", styles["small"]),
            Paragraph(rec.published, styles["small"]),
            Paragraph(
                rec.description[:200] + ("..." if len(rec.description) > 200 else ""),
                styles["small"],
            ),
        ])

        # Colour the severity cell
        sev_color = SEVERITY_COLORS.get(sev, _C_UNKNOWN)
        row_style_commands += [
            ("BACKGROUND", (5, i), (5, i), sev_color),
            ("TEXTCOLOR",  (5, i), (5, i),
             colors.white if sev != "MEDIUM" else _C_NAVY),
        ]
        # Colour KEV cell
        if rec.is_kev:
            row_style_commands += [
                ("BACKGROUND", (6, i), (6, i), _C_KEV),
                ("TEXTCOLOR",  (6, i), (6, i), colors.white),
            ]
        # Highlight entire KEV row with a subtle left border effect
        if rec.is_kev:
            row_style_commands += [
                ("BACKGROUND", (0, i), (0, i), colors.HexColor("#F4ECF7")),
            ]

    col_widths = [
        26 * mm, 20 * mm, 20 * mm, 12 * mm, 10 * mm,
        17 * mm, 9 * mm, 9 * mm, 16 * mm, 33 * mm,
    ]
    table = Table(rows, colWidths=col_widths, repeatRows=1)
    table.setStyle(_header_table_style(row_style_commands))
    story.append(table)


def _build_remediation_section(
    styles: dict[str, ParagraphStyle],
    story: list,
) -> None:
    """Render the remediation SLA reference section."""
    story.append(Paragraph("Remediation Priority Reference", styles["section"]))

    sla_data = [
        ["Classification",            "Patch SLA",   "Authority",           "Guidance"],
        ["KEV — Ransomware Linked",   "14 days",     "CISA BOD 22-01",      "Isolate immediately if exploitation is confirmed. Escalate to incident response."],
        ["KEV — Confirmed Exploited", "14 days",     "CISA BOD 22-01",      "Apply vendor patch or compensating control. Monitor threat intelligence feeds."],
        ["CRITICAL (CVSS 9.0–10.0)",  "30 days",     "NIST SP 800-40r4",    "Patch in the current change cycle. Apply interim mitigations if patching is delayed."],
        ["HIGH (CVSS 7.0–8.9)",       "60 days",     "NIST SP 800-40r4",    "Schedule within the next patch cycle. Review exploit availability."],
        ["MEDIUM (CVSS 4.0–6.9)",     "90 days",     "Organisational SLA",  "Include in quarterly patch planning. Document accepted risk if deferred."],
        ["LOW (CVSS 0.1–3.9)",        "180 days",    "Organisational SLA",  "Schedule during routine maintenance. Formal risk acceptance required if >180 days."],
    ]

    row_style_commands = [
        ("BACKGROUND", (0, 0), (-1, 0), _C_NAVY),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("BACKGROUND", (0, 1), (0, 1), colors.HexColor("#4A0082")),
        ("TEXTCOLOR",  (0, 1), (0, 1), colors.white),
        ("BACKGROUND", (0, 2), (0, 2), _C_KEV),
        ("TEXTCOLOR",  (0, 2), (0, 2), colors.white),
        ("BACKGROUND", (0, 3), (0, 3), _C_CRITICAL),
        ("TEXTCOLOR",  (0, 3), (0, 3), colors.white),
        ("BACKGROUND", (0, 4), (0, 4), _C_HIGH),
        ("TEXTCOLOR",  (0, 4), (0, 4), colors.white),
        ("BACKGROUND", (0, 5), (0, 5), _C_MEDIUM),
        ("TEXTCOLOR",  (0, 5), (0, 5), _C_NAVY),
        ("BACKGROUND", (0, 6), (0, 6), _C_LOW),
        ("TEXTCOLOR",  (0, 6), (0, 6), colors.white),
        ("FONTNAME",   (0, 1), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 7),
    ]

    table = Table(
        sla_data,
        colWidths=[42 * mm, 18 * mm, 30 * mm, 80 * mm],
    )
    table.setStyle(_header_table_style(row_style_commands))
    story.append(table)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def generate_pdf_report(
    cves: list[CVERecord],
    assets: Sequence[SoftwareAsset],
    kev_count: int = 0,
    kev_catalog_version: str = "N/A",
    output_dir: Path = OUTPUT_DIR,
) -> Path:
    """Generate a PDF risk report and return the output file path.

    Parameters
    ----------
    cves : list[CVERecord]
        KEV-enriched CVE records from the NVD scan.
    assets : Sequence[SoftwareAsset]
        The full list of scanned assets.
    kev_count : int
        Number of CVEs matched to the CISA KEV catalog.
    kev_catalog_version : str
        Version string of the CISA KEV catalog used for enrichment.
    output_dir : Path
        Directory in which to save the PDF. Created if not present.

    Returns
    -------
    Path
        Absolute path to the generated PDF.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = output_dir / f"VulnScan_Report_{timestamp}.pdf"

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="Automated Vulnerability Scan Report",
        author="NVD-VulnScanner",
    )

    styles = _build_styles()
    story: list = []

    # ---- Title block ------------------------------------------------------- #
    story.append(Paragraph("Automated Vulnerability Scan Report", styles["title"]))
    story.append(
        Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  "
            f"Assets Scanned: {len(list(assets))}  |  "
            f"CVEs Identified: {len(cves)}  |  "
            f"KEV Matches: {kev_count}  |  "
            f"CISA KEV Catalog: {kev_catalog_version}",
            styles["subtitle"],
        )
    )
    story.append(
        HRFlowable(width="100%", thickness=1.5, color=_C_NAVY, spaceAfter=4)
    )
    story.append(Spacer(1, 4 * mm))

    # ---- KEV section (highest priority) ------------------------------------ #
    kev_cves = [r for r in cves if r.is_kev]
    _build_kev_section(kev_cves, styles, story)
    story.append(Spacer(1, 5 * mm))

    # ---- Executive summary ------------------------------------------------- #
    _build_summary_section(cves, kev_count, styles, story)
    story.append(Spacer(1, 5 * mm))

    # ---- Asset inventory --------------------------------------------------- #
    _build_inventory_section(assets, styles, story)
    story.append(Spacer(1, 5 * mm))

    # ---- Full CVE detail --------------------------------------------------- #
    _build_cve_detail_section(cves, styles, story)
    story.append(Spacer(1, 5 * mm))

    # ---- Remediation reference --------------------------------------------- #
    _build_remediation_section(styles, story)
    story.append(Spacer(1, 6 * mm))

    # ---- Footer ------------------------------------------------------------ #
    story.append(HRFlowable(width="100%", thickness=0.4, color=_C_RULE))
    story.append(
        Paragraph(
            f"CONFIDENTIAL — Automated Vulnerability Scan Report  |  "
            f"Data source: NIST NVD API v2 + CISA KEV Catalog  |  "
            f"Generated: {datetime.now().strftime('%Y-%m-%d')}  |  "
            f"This report requires review by a qualified security professional "
            f"prior to remediation action.",
            styles["footer"],
        )
    )

    doc.build(story)
    log.info("PDF report saved: %s", output_path.resolve())
    return output_path
