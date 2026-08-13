import unittest
from unittest.mock import patch, MagicMock
from scanner.models import SoftwareAsset, CVERecord, KEVEntry
from scanner.cisa_kev import KEVCatalog

class TestKEVCatalog(unittest.TestCase):
    def test_lookup_existing(self):
        entries = {
            "CVE-2021-44228": KEVEntry(
                cve_id="CVE-2021-44228",
                vulnerability_name="Log4Shell",
                vendor_project="Apache",
                product="Log4j",
                date_added="2021-12-10",
                due_date="2021-12-24",
                known_ransomware=True,
                required_action="Update"
            )
        }
        catalog = KEVCatalog(entries, "2021.12.10")
        
        result = catalog.lookup("CVE-2021-44228")
        self.assertIsNotNone(result)
        self.assertEqual(result.vulnerability_name, "Log4Shell")
        self.assertTrue(result.known_ransomware)

    def test_lookup_missing(self):
        catalog = KEVCatalog({}, "2021.12.10")
        result = catalog.lookup("CVE-2021-44228")
        self.assertIsNone(result)

    def test_enrich(self):
        entries = {
            "CVE-2021-44228": KEVEntry(
                cve_id="CVE-2021-44228",
                vulnerability_name="Log4Shell",
                vendor_project="Apache",
                product="Log4j",
                date_added="2021-12-10",
                due_date="2021-12-24",
                known_ransomware=True,
                required_action="Update"
            )
        }
        catalog = KEVCatalog(entries, "2021.12.10")
        
        asset = SoftwareAsset(host="server1", vendor="apache", product="log4j", version="2.14.0")
        cves = [
            CVERecord(
                cve_id="CVE-2021-44228",
                description="Log4Shell",
                cvss_score=10.0,
                cvss_severity="CRITICAL",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cvss_version="3.1",
                published="2021-12-10",
                last_modified="2021-12-10",
                asset=asset
            ),
            CVERecord(
                cve_id="CVE-2020-1234",
                description="Dummy",
                cvss_score=5.0,
                cvss_severity="MEDIUM",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cvss_version="3.1",
                published="2020-01-01",
                last_modified="2020-01-01",
                asset=asset
            )
        ]
        
        enriched_cves, match_count = catalog.enrich(cves)
        
        self.assertEqual(match_count, 1)
        self.assertIsNotNone(enriched_cves[0].kev_entry)
        self.assertIsNone(enriched_cves[1].kev_entry)

if __name__ == '__main__':
    unittest.main()
