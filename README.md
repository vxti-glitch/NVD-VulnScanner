# NVD Automated Vulnerability & Asset Scanner

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![NVD API](https://img.shields.io/badge/NVD_API-v2-003087?style=flat-square)
![CISA KEV](https://img.shields.io/badge/CISA_KEV-Integrated-8B0000?style=flat-square)
![ReportLab](https://img.shields.io/badge/ReportLab-PDF_Engine-FF6B35?style=flat-square)
![Async](https://img.shields.io/badge/I%2FO-Async_aiohttp-009688?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-22A7F0?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=flat-square)
![Status](https://img.shields.io/badge/Status-Production--Ready-27AE60?style=flat-square)

---

## Overview

A Python-based vulnerability management tool that correlates a Windows software asset inventory against two authoritative threat intelligence sources: the NIST National Vulnerability Database (NVD) CVE API v2 and the CISA Known Exploited Vulnerabilities (KEV) catalog. Output is a structured, timestamped PDF risk report suitable for IT operations review, change-management documentation, and security audit evidence.

The scanner constructs well-formed CPE 2.3 strings from inventory data, submits them asynchronously to the NVD CVE API v2, cross-references results against the CISA KEV catalog, and renders a paginated PDF report. It replicates a core function performed by commercial vulnerability management platforms without licensing cost, and is suitable for small-to-mid-size enterprise environments or for validating the output of paid tooling.

---

## Business Value

### The Cost of Reactive Security

Organisations that operate without a continuous vulnerability management programme default to a reactive security posture. Threat actors routinely exploit publicly disclosed CVEs within 15 days of publication â€” before most IT teams complete manual patch cycles. The average cost of a data breach is $4.88 million USD (IBM Cost of a Data Breach Report, 2024), significantly higher for organisations lacking systematic patch and vulnerability workflows.

This tool directly addresses the following operational gaps:

| Gap | Resolution |
|---|---|
| No centralised software inventory | Simulated inventory models real WMI/CMDB data structures; CSV input supports live data ingestion |
| No CVE-to-asset correlation | Constructs CPE 2.3 strings per asset and queries NVD API v2 in real time |
| No CISA KEV cross-reference | Enriches CVEs with confirmed exploitation evidence from the CISA KEV catalog |
| Manual, ad-hoc patch prioritisation | CVSS-based severity ranking with CISA BOD 22-01 patch SLA timelines embedded in report output |
| No audit-ready documentation | Timestamped PDF provides a repeatable, version-controlled scan artefact |
| High cost of commercial scanners | Zero licensing cost; integrates with standard Python environments |

Proactive vulnerability identification compresses Mean Time to Remediate (MTTR) by providing IT operations teams with structured, prioritised output instead of raw advisory feeds. KEV cross-referencing further tightens patch windows by surfacing vulnerabilities with confirmed real-world exploitation â€” the highest-urgency signal available from public threat intelligence.

---

## Architecture

```
assets.csv  /  built-in simulated inventory
         |
         v
   scanner.inventory.load_inventory()
   -> list[SoftwareAsset]
         |
         v
   SoftwareAsset.cpe_string
   cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*
         |
   ------+------
   |           |
   v           v
NVDClient    KEVCatalog.fetch()
(async,      (concurrent with
 rate-limit   NVD scan)
 aware)
   |           |
   v           v
list[CVERecord] + KEVCatalog.enrich()
         |
         v
   CVSS threshold filter  (--threshold)
         |
         v
   scanner.report.generate_pdf_report()
   reports/VulnScan_Report_<TIMESTAMP>.pdf
```

**Concurrency model:** The CISA KEV catalog fetch and all NVD CPE queries are dispatched concurrently via `asyncio.gather`. A `Semaphore(1)` with a per-request sleep paces NVD queries within the API rate limit. Exponential backoff (base 2 s, ceiling 60 s) handles HTTP 429 and 503 responses with up to 4 attempts per asset.

---

## Features

- Software inventory simulation representing a realistic multi-host enterprise environment
- External CSV inventory ingestion for live or CMDB-sourced asset data
- Async NVD API v2 integration with authenticated (API key) and unauthenticated modes
- CPE 2.3 string construction per software asset
- CVSS scoring with v3.1 / v3.0 / v2.0 fallback hierarchy
- Concurrent CISA KEV catalog fetch with O(1) CVE cross-reference lookup
- KEV enrichment: ransomware-association flag, CISA patch due date, required action
- Rate-limit-aware request cadencing with exponential backoff retry
- CVSS score threshold filtering via CLI flag
- Structured PDF output containing:
  - Timestamped report header with KEV catalog version
  - Actively Exploited section (KEV matches only â€” highest priority)
  - Executive summary with severity distribution and SLA guidance
  - Full asset inventory table with CPE strings
  - Vulnerability detail table sorted by priority rank (KEV > CRITICAL > HIGH > MEDIUM > LOW)
  - CVSS and CISA BOD 22-01 remediation SLA reference table
- Structured console logging throughout execution

---

## Requirements

- Python 3.10 or later
- Internet access to `services.nvd.nist.gov` and `www.cisa.gov`
- (Optional) NVD API key for higher request throughput

---

## Installation

```bash
git clone https://github.com/<your-username>/NVD-VulnScanner.git
cd NVD-VulnScanner
pip install -r requirements.txt
```

---

## How to Use

### 1. Default Mode â€” Simulated Inventory

Run the scanner without arguments. The built-in inventory of 10 enterprise software packages with known historic CVE exposure is used.

```bash
python main.py
```

The PDF report is written to `reports/VulnScan_Report_<TIMESTAMP>.pdf`.

---

### 2. Custom Inventory via CSV

Create an `assets.csv` file. If present in the current directory, it takes precedence over the built-in inventory. Pass the path explicitly via `--inventory`:

```csv
host,vendor,product,version
WS-FINANCE-01,adobe,acrobat_reader,2020.001.30005
SRV-WEB-01,apache,http_server,2.4.49
WS-HR-02,apache,log4j,2.14.0
```

```bash
python main.py --inventory assets.csv
```

See `assets.csv.example` for a complete reference file.

---

### 3. Authenticated Mode â€” Higher Rate Limit

Register for a free NVD API key at [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key). With a key, the rate limit increases from 5 to 50 requests per 30-second window, substantially reducing scan time on large inventories.

**Windows (PowerShell):**
```powershell
$env:NVD_API_KEY = "your-api-key-here"
python main.py
```

**Linux / macOS:**
```bash
export NVD_API_KEY="your-api-key-here"
python main.py
```

Or pass the key directly via CLI flag:

```bash
python main.py --key your-api-key-here
```

---

### 4. CLI Reference

```
python main.py [--inventory PATH] [--threshold SCORE] [--output DIR] [--key API_KEY] [--dry-run]
```

| Flag | Default | Description |
|---|---|---|
| `--inventory PATH` | Auto-detect / simulated | Path to CSV inventory file |
| `--threshold SCORE` | `0.0` | Minimum CVSS base score to include (0.0-10.0) |
| `--output DIR` | `reports/` | Output directory for PDF reports |
| `--key API_KEY` | `NVD_API_KEY` env var | NVD API key |
| `--dry-run` | Off | Validate inventory only; skip API calls |

**Examples:**

```bash
# Filter to CVSS >= 7.0 (HIGH and CRITICAL only)
python main.py --threshold 7.0

# Custom output directory with API key
python main.py --key YOUR_KEY --output /var/reports/vuln

# Validate CSV format before a full scan
python main.py --inventory assets.csv --dry-run
```

---

## Report Structure

| Section | Content |
|---|---|
| Title Block | Scan timestamp, assets scanned, total CVEs, KEV matches, CISA catalog version |
| Actively Exploited | KEV-matched CVEs only â€” ransomware flag, CISA due date, required action |
| Executive Summary | Severity distribution table with patch SLA per tier |
| Asset Inventory | All scanned hosts with vendor, product, version, CPE string |
| Full Vulnerability Detail | All CVEs sorted by priority rank â€” includes KEV flag, SLA days, CVSS vector |
| Remediation Reference | CISA BOD 22-01 and NIST SP 800-40r4 SLA guidance by classification |
| Footer | Classification marking, data source attribution, generation timestamp |

Reports are saved to `reports/` with a timestamp in the filename, enabling historical comparison across successive scans.

---

## NVD API Rate Limits

| Mode | Rate Limit | Inter-Request Delay |
|---|---|---|
| Unauthenticated | 5 requests / 30 seconds | 6.0 seconds |
| Authenticated (API key) | 50 requests / 30 seconds | 0.6 seconds |

The client enforces these limits via `asyncio.Semaphore` and per-request sleep. HTTP 429 and 503 responses trigger exponential backoff with up to 4 attempts per asset.

---

## Limitations

- CPE string accuracy depends on the vendor and product naming conventions indexed by NVD. Software not indexed under the queried vendor/product name returns zero results. Manual CPE validation via the NVD CPE Dictionary (`https://nvd.nist.gov/products/cpe/search`) is recommended for production deployments.
- The tool performs read-only API queries. It does not perform active network scanning, port enumeration, or service fingerprinting.
- CVE data reflects the NVD dataset at query time. NVD processing latency can delay the appearance of newly disclosed CVEs by 24-72 hours after publication.
- CISA KEV catalog availability depends on CISA infrastructure. A fetch failure does not abort the scan â€” NVD data remains valid without KEV enrichment.

---

## Project Structure

```
NVD-VulnScanner/
â”œâ”€â”€ main.py               # CLI entrypoint â€” async orchestration pipeline
â”œâ”€â”€ vuln_scanner.py       # Standalone legacy version (synchronous, single-file)
â”œâ”€â”€ scanner/
â”‚   â”œâ”€â”€ __init__.py
â”‚   â”œâ”€â”€ models.py         # Core dataclasses: SoftwareAsset, CVERecord, KEVEntry
â”‚   â”œâ”€â”€ inventory.py      # Asset loading: CSV and simulated inventory
â”‚   â”œâ”€â”€ nvd_client.py     # Async NVD API v2 client with rate-limit management
â”‚   â”œâ”€â”€ cisa_kev.py       # CISA KEV catalog fetch, index, and CVE enrichment
â”‚   â””â”€â”€ report.py         # PDF risk report generation via ReportLab
â”œâ”€â”€ requirements.txt      # Python dependencies
â”œâ”€â”€ assets.csv.example    # Reference CSV inventory format
â”œâ”€â”€ reports/              # PDF output directory (auto-created at runtime)
â””â”€â”€ README.md
```

---

## License

MIT License. See `LICENSE` for full terms.

---

## Data Sources

- **National Vulnerability Database (NVD)** â€” NIST. [https://nvd.nist.gov](https://nvd.nist.gov)
- **CISA Known Exploited Vulnerabilities Catalog** â€” CISA. [https://www.cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- **Common Platform Enumeration (CPE)** â€” MITRE / NIST. [https://cpe.mitre.org](https://cpe.mitre.org)
- **Common Vulnerability Scoring System (CVSS)** â€” FIRST.org. [https://www.first.org/cvss](https://www.first.org/cvss)
- **CISA Binding Operational Directive 22-01** â€” [https://www.cisa.gov/binding-operational-directive-22-01](https://www.cisa.gov/binding-operational-directive-22-01)
