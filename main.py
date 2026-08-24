"""
main.py — NVD Automated Vulnerability & Asset Scanner
======================================================
CLI entrypoint. Orchestrates:
  1. Asset inventory loading (CSV or simulated)
  2. Concurrent CISA KEV catalog fetch + NVD asset queries
  3. KEV cross-reference enrichment pass
  4. PDF report generation

Usage
-----
    python main.py [--inventory PATH] [--threshold SCORE]
                   [--output DIR] [--key API_KEY] [--dry-run]

Environment variables
---------------------
    NVD_API_KEY : NVD API key (optional; overridden by --key flag).
                  Raises NVD rate limit from 5 req/30s to 50 req/30s.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

import aiohttp

from scanner.cisa_kev import KEVCatalog
from scanner.inventory import load_inventory
from scanner.nvd_client import NVDClient
from scanner.report import OUTPUT_DIR, generate_pdf_report

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)-8s]  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------
def _cvss_threshold(value: str) -> float:
    try:
        score = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("threshold must be a number") from exc

    if not 0.0 <= score <= 10.0:
        raise argparse.ArgumentTypeError("threshold must be between 0.0 and 10.0")
    return score


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nvd-vulnscanner",
        description=(
            "Automated Vulnerability & Asset Scanner — "
            "correlates software inventory against NVD CVE and CISA KEV data."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with built-in simulated inventory:
  python main.py

  # Run with a custom CSV inventory:
  python main.py --inventory assets.csv

  # Run with NVD API key and custom output directory:
  python main.py --key YOUR_API_KEY --output /reports

  # Filter to CVSS >= 7.0 only:
  python main.py --threshold 7.0

  # Dry-run (validate inventory, skip API calls):
  python main.py --dry-run
""",
    )
    parser.add_argument(
        "--inventory",
        metavar="PATH",
        type=Path,
        default=None,
        help=(
            "Path to a CSV inventory file (columns: host, vendor, product, version). "
            "If omitted, uses assets.csv in the current directory, "
            "or falls back to the built-in simulated inventory."
        ),
    )
    parser.add_argument(
        "--threshold",
        metavar="SCORE",
        type=_cvss_threshold,
        default=0.0,
        help=(
            "Minimum CVSS base score to include in the report (0.0–10.0). "
            "Default: 0.0 (all severities)."
        ),
    )
    parser.add_argument(
        "--output",
        metavar="DIR",
        type=Path,
        default=OUTPUT_DIR,
        help="Output directory for PDF reports. Default: reports/",
    )
    parser.add_argument(
        "--key",
        metavar="API_KEY",
        type=str,
        default=None,
        help=(
            "NVD API key. Overrides the NVD_API_KEY environment variable. "
            "Obtain a free key at https://nvd.nist.gov/developers/request-an-api-key"
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help=(
            "Load and validate the inventory, then exit without making API calls. "
            "Useful for verifying CSV format before a full scan."
        ),
    )
    return parser


# ---------------------------------------------------------------------------
# Async main
# ---------------------------------------------------------------------------
async def _run(args: argparse.Namespace) -> int:
    """Core async pipeline. Returns an exit code (0 = success)."""

    log.info("=" * 60)
    log.info("NVD Automated Vulnerability & Asset Scanner v2")
    log.info("=" * 60)

    # ---- Step 1: Load inventory ------------------------------------------ #
    try:
        assets = load_inventory(args.inventory)
    except FileNotFoundError as exc:
        log.error("Inventory file not found: %s", exc)
        return 1
    except ValueError as exc:
        log.error("Inventory file format error: %s", exc)
        return 1

    if not assets:
        log.error("No assets found in inventory — nothing to scan.")
        return 1

    log.info("Inventory: %d assets across %d host(s).", len(assets), len({a.host for a in assets}))

    # ---- Dry-run exit ------------------------------------------------------ #
    if args.dry_run:
        log.info("Dry-run mode: inventory validated successfully. Exiting.")
        for a in assets:
            log.info("  %s", a)
        return 0

    # ---- Step 2: Resolve API key ------------------------------------------ #
    api_key: str | None = args.key or os.environ.get("NVD_API_KEY")
    if not api_key:
        log.warning(
            "NVD_API_KEY not set. Operating at public rate limit "
            "(5 requests / 30 seconds). Scan of %d assets will take "
            "approximately %.0f seconds.",
            len(assets),
            len(assets) * 6.0,
        )
    else:
        log.info("NVD API key detected — authenticated rate limit active (50 req/30s).")

    # ---- Step 3: Fetch KEV catalog + scan assets concurrently -------------- #
    # The KEV catalog fetch and NVD queries use separate sessions because they
    # hit different hosts with different headers.
    async with NVDClient(api_key=api_key) as nvd_client:
        # Run KEV catalog fetch concurrently with the first NVD request
        # by creating a shared aiohttp session for the KEV fetch only.
        kev_session = aiohttp.ClientSession(headers={"Accept": "application/json"})

        try:
            # Fire KEV fetch and full NVD scan concurrently
            kev_task = asyncio.create_task(KEVCatalog.fetch(kev_session))
            cve_task = asyncio.create_task(nvd_client.scan_assets(assets))

            kev_catalog, cves = await asyncio.gather(kev_task, cve_task)
        finally:
            await kev_session.close()

    # ---- Step 4: Apply CVSS threshold filter ------------------------------ #
    if args.threshold > 0.0:
        before = len(cves)
        cves = [c for c in cves if c.cvss_score >= args.threshold]
        log.info(
            "CVSS threshold %.1f applied: %d of %d CVE(s) retained.",
            args.threshold,
            len(cves),
            before,
        )

    # ---- Step 5: KEV enrichment cross-reference --------------------------- #
    cves, kev_match_count = kev_catalog.enrich(cves)
    log.info(
        "KEV enrichment complete: %d of %d CVE(s) matched the CISA KEV catalog.",
        kev_match_count,
        len(cves),
    )

    # ---- Step 6: Generate PDF report -------------------------------------- #
    report_path = generate_pdf_report(
        cves=cves,
        assets=assets,
        kev_count=kev_match_count,
        kev_catalog_version=kev_catalog.catalog_version,
        output_dir=args.output,
    )

    log.info("=" * 60)
    log.info("Scan complete.")
    log.info("  Total CVEs : %d", len(cves))
    log.info("  KEV matches: %d", kev_match_count)
    log.info("  Report     : %s", report_path.resolve())
    log.info("=" * 60)

    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    exit_code = asyncio.run(_run(args))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
