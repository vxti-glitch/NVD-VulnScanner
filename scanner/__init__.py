"""
Candidate CVE correlation package for reviewed software-to-CPE mappings.

Modules
-------
models      : Core dataclasses (SoftwareAsset, CVERecord, KEVEntry)
inventory   : Asset loading from CSV or built-in simulated inventory
nvd_client  : Async NVD API v2 client with rate-limit-aware concurrency
cisa_kev    : CISA Known Exploited Vulnerabilities catalog integration
report      : PDF risk report generation via ReportLab
"""
