"""
scanner.inventory
=================
Asset inventory loading — CSV-based and built-in simulated.

Design notes (Backend Architect)
---------------------------------
- CSV loading is decoupled from the NVD client: the inventory layer is
  purely I/O and data-shaping; it has no knowledge of vulnerability APIs.
- The simulated inventory targets historically CVE-dense software versions
  selected to produce meaningful NVD results during portfolio demos.
- `load_inventory()` is the single entry point; callers do not need to
  choose between CSV and simulated — the function does that automatically.
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path

from .models import SoftwareAsset

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Simulated inventory
# Represents a realistic mid-size enterprise environment with a mix of
# workstations, web servers, and database servers. Versions are deliberately
# historic to guarantee NVD coverage during demonstrations.
# ---------------------------------------------------------------------------
_SIMULATED: list[dict[str, str]] = [
    # Remote code execution — Log4Shell (CVE-2021-44228)
    {"host": "WS-HR-02",    "vendor": "apache",       "product": "log4j",            "version": "2.14.0"},
    # Path traversal — Apache 2.4.49 (CVE-2021-41773)
    {"host": "SRV-WEB-01",  "vendor": "apache",       "product": "http_server",      "version": "2.4.49"},
    # OpenSSL heartbleed era
    {"host": "SRV-WEB-01",  "vendor": "openssl",      "product": "openssl",          "version": "1.0.1"},
    # Spring4Shell (CVE-2022-22965)
    {"host": "SRV-APP-01",  "vendor": "springproject", "product": "spring_framework", "version": "5.3.17"},
    # Adobe Acrobat Reader historic CVEs
    {"host": "WS-FINANCE-01","vendor": "adobe",        "product": "acrobat_reader",   "version": "2020.001.30005"},
    # PHP 7.2.x multiple CVEs
    {"host": "SRV-WEB-01",  "vendor": "php",          "product": "php",              "version": "7.2.0"},
    # MySQL 5.7 privilege escalation vectors
    {"host": "SRV-DB-01",   "vendor": "oracle",       "product": "mysql",            "version": "5.7.35"},
    # PuTTY pre-0.75 stack overflow
    {"host": "WS-OPS-03",   "vendor": "putty",        "product": "putty",            "version": "0.73"},
    # Internet Explorer EOL CVEs
    {"host": "WS-FINANCE-01","vendor": "microsoft",   "product": "internet_explorer", "version": "11.0"},
    # 7-zip older version
    {"host": "WS-OPS-03",   "vendor": "7-zip",        "product": "7-zip",            "version": "19.00"},
]


def load_inventory_from_csv(csv_path: Path) -> list[SoftwareAsset]:
    """Parse a CSV file into a list of SoftwareAsset objects.

    Expected columns (header row required): host, vendor, product, version
    Rows with missing or empty required fields are skipped with a warning.

    Parameters
    ----------
    csv_path : Path
        Absolute or relative path to the CSV inventory file.

    Returns
    -------
    list[SoftwareAsset]
        Validated asset records parsed from the file.

    Raises
    ------
    FileNotFoundError
        If csv_path does not exist.
    csv.Error
        If the file is not valid CSV.
    """
    required_columns = {"host", "vendor", "product", "version"}
    assets: list[SoftwareAsset] = []
    skipped = 0

    with csv_path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)

        # Validate header
        if reader.fieldnames is None:
            log.warning("CSV file appears empty: %s", csv_path)
            return []

        actual_cols = {c.strip().lower() for c in reader.fieldnames}
        missing_cols = required_columns - actual_cols
        if missing_cols:
            raise ValueError(
                f"CSV is missing required columns: {missing_cols}. "
                f"Found: {actual_cols}"
            )

        for lineno, row in enumerate(reader, start=2):
            host = row.get("host", "").strip()
            vendor = row.get("vendor", "").strip()
            product = row.get("product", "").strip()
            version = row.get("version", "").strip()

            if not all([host, vendor, product, version]):
                log.warning(
                    "Skipping incomplete row at line %d in %s: %s",
                    lineno,
                    csv_path.name,
                    dict(row),
                )
                skipped += 1
                continue

            assets.append(
                SoftwareAsset(
                    host=host,
                    vendor=vendor,
                    product=product,
                    version=version,
                )
            )

    log.info(
        "CSV inventory loaded: %d assets from %s (%d rows skipped).",
        len(assets),
        csv_path.name,
        skipped,
    )
    return assets


def load_simulated_inventory() -> list[SoftwareAsset]:
    """Return the built-in simulated enterprise inventory."""
    assets = [SoftwareAsset(**r) for r in _SIMULATED]
    log.info(
        "Simulated inventory loaded: %d assets across %d hosts.",
        len(assets),
        len({a.host for a in assets}),
    )
    return assets


def load_inventory(csv_path: Path | None = None) -> list[SoftwareAsset]:
    """Unified inventory loader.

    If `csv_path` is provided and exists, load from that file.
    If `csv_path` is None, fall back to checking for `assets.csv` in the
    current working directory. If neither exists, use the simulated inventory.

    Parameters
    ----------
    csv_path : Path | None
        Explicit path to inventory CSV, or None for auto-detection.
    """
    # Explicit path provided
    if csv_path is not None:
        if not csv_path.exists():
            raise FileNotFoundError(f"Inventory file not found: {csv_path}")
        return load_inventory_from_csv(csv_path)

    # Auto-detect assets.csv in cwd
    default_csv = Path("assets.csv")
    if default_csv.exists():
        log.info("Auto-detected inventory file: %s", default_csv.resolve())
        return load_inventory_from_csv(default_csv)

    # Fall back to simulated inventory
    log.info("No inventory file found — using built-in simulated inventory.")
    return load_simulated_inventory()
