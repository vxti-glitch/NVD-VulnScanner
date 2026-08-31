"""CSV inventory loading with explicit, reviewable CPE mappings."""

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
_SIMULATED: list[dict[str, object]] = [
    # Remote code execution — Log4Shell (CVE-2021-44228)
    {"host": "LAB-WS-01", "vendor": "Apache", "product": "Log4j", "version": "2.14.0", "reviewed_cpe": "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*", "mapping_source": "NVD CPE Dictionary review"},
    # Path traversal — Apache 2.4.49 (CVE-2021-41773)
    {"host": "LAB-SRV-01", "vendor": "Example Vendor", "product": "Unmapped Product", "version": "1.0"},
    # OpenSSL heartbleed era
    {"host": "LAB-WS-02", "vendor": "Example", "product": "Ambiguous Agent", "version": "2.0", "candidate_cpes": ("cpe:2.3:a:example:agent:2.0:*:*:*:*:*:*:*", "cpe:2.3:a:example:agent_pro:2.0:*:*:*:*:*:*:*")},
    # Spring4Shell (CVE-2022-22965)
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

            reviewed_cpe = (row.get("reviewed_cpe") or "").strip() or None
            mapping_source = (row.get("mapping_source") or "").strip() or None
            candidates = tuple(
                item.strip()
                for item in (row.get("candidate_cpes") or "").split("|")
                if item.strip()
            )
            assets.append(SoftwareAsset(
                host=host, vendor=vendor, product=product, version=version,
                reviewed_cpe=reviewed_cpe, mapping_source=mapping_source,
                candidate_cpes=candidates,
            ))

    log.info(
        "CSV inventory loaded: %d assets from %s (%d rows skipped).",
        len(assets),
        csv_path.name,
        skipped,
    )
    return assets


def load_simulated_inventory() -> list[SoftwareAsset]:
    """Return a small synthetic mapping-state fixture inventory."""
    assets = [SoftwareAsset(**r) for r in _SIMULATED]
    log.info(
        "Synthetic fixture inventory loaded: %d records across %d hosts.",
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
    log.info("No inventory file found — using built-in synthetic fixture inventory.")
    return load_simulated_inventory()
