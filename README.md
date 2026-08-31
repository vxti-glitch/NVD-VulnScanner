# NVD Inventory Correlation Helper

This is a cautious inventory-to-NVD/KEV correlation helper. It accepts software inventory records, queries NVD only when a CPE 2.3 name has been explicitly reviewed, adds CISA Known Exploited Vulnerabilities context, and produces a PDF for human review.

It is not an endpoint or network scanner, a replacement for a vulnerability-management platform, compliance evidence, or an authoritative remediation system. A returned CVE is a candidate match to the reviewed CPE—not proof that the software is installed, affected, reachable, or exploitable.

## Mapping safety boundary

The tool never constructs a CPE by lowercasing product names or replacing spaces. Each inventory row has one of three states:

- `matched`: one valid `reviewed_cpe` and its `mapping_source` were supplied; NVD may be queried.
- `ambiguous`: multiple reviewable `candidate_cpes` remain; no CVE query is made.
- `unresolved`: no reviewed mapping exists; no CVE query is made.

The correlator never silently selects among candidates. Operators should review NVD CPE Dictionary results, vendor identifiers, product edition, platform, and version scope before supplying `reviewed_cpe`.

## Inputs

CSV columns:

```text
host,vendor,product,version,reviewed_cpe,mapping_source,candidate_cpes
```

`reviewed_cpe` and `mapping_source` are optional together. Separate multiple unreviewed candidates with `|`. `assets.csv.example` is synthetic fixture data and includes matched, unresolved, and ambiguous examples.

Safer inventory sources include reviewed CMDB/asset exports, endpoint-management inventory, package-manager records, uninstall registry entries, and vendor-specific inventory tools. Coverage and naming vary, so no source should be assumed universally complete. `Win32_Product` is not recommended because querying it can trigger Windows Installer consistency checks and it covers only MSI-installed products.

## Install and run

```powershell
git clone https://github.com/vxti-glitch/NVD-VulnScanner.git
cd NVD-VulnScanner
python -m pip install -r requirements.txt
python main.py --inventory .\assets.csv.example --dry-run
python main.py --inventory .\assets.csv.example --offline-fixtures .\tests\fixtures
```

Use `--key` or `NVD_API_KEY` for an NVD API key. `--threshold` filters candidate CVEs by CVSS after correlation. Non-KEV targets are configurable sample organizational policy:

```powershell
python main.py --inventory .\assets.csv.example `
  --target-critical 14 --target-high 30 --target-medium 90 --target-low 180
```

Those values are not NIST deadlines. NIST SP 800-40 Rev. 4 describes enterprise patch-management planning and risk response; it does not establish this tool's 30/60/90/180-day sample targets.

## KEV applicability

The report preserves each KEV entry's actual `dueDate`. CISA Binding Operational Directive 22-01 is binding on U.S. federal civilian executive branch agencies. Other organizations can use KEV as a prioritization input under their own risk, change, and approval policies.

## Output limits

The PDF is named `NVD_Correlation_Report_<timestamp>.pdf`. It includes mapping status, reviewed CPEs or unresolved candidates, candidate CVEs only for reviewed mappings, CVSS data, KEV context, and sample organizational targets. Every mapping, applicability decision, and remediation action requires authorized human review. Empty or unavailable KEV data must be treated as unknown KEV enrichment—not evidence that no candidate is exploited.

## Tests

Recorded NVD and CISA fixtures cover explicit mappings, unresolved and ambiguous records, the KEV entry due date, non-FCEB wording, configurable targets, retry behavior, stale/malformed fixtures, and the no-CVE-without-mapping boundary.

```powershell
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python -m compileall scanner tests
```

The live integration check is opt-in and skipped by default:

```powershell
$env:RUN_LIVE_NVD_TESTS = '1'
python -m unittest tests.test_live_integration -v
```

Ordinary CI and recorded-fixture tests do not prove current NVD/CISA availability, endpoint inventory quality, live system exposure, or remediation correctness.

## Sources

Official sources checked 2026-08-31:

- [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities)
- [NVD CPE API and dictionary guidance](https://nvd.nist.gov/developers/products)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA BOD 22-01](https://www.cisa.gov/news-events/directives/bod-22-01-reducing-significant-risk-known-exploited-vulnerabilities)
- [NIST SP 800-40 Rev. 4](https://csrc.nist.gov/pubs/sp/800/40/r4/final)
- [Microsoft guidance on Win32_Product side effects](https://learn.microsoft.com/en-us/troubleshoot/windows-server/admin-development/windows-installer-reconfigured-all-applications)

## Portfolio boundary

This repository contains code, synthetic inventory, recorded API fixtures, and offline tests. It does not contain evidence of a production deployment, a completed enterprise vulnerability program, or live endpoint validation.
