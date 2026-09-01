import unittest
from datetime import date
from pathlib import Path
from tempfile import TemporaryDirectory

from main import _build_parser
from scanner.inventory import load_inventory_from_csv
from scanner.models import SoftwareAsset, CVERecord, KEVEntry
from scanner.cisa_kev import KEVCatalog
from scanner.nvd_client import NVDClient
from scanner.fixtures import RecordedFixtureError, load_recorded_fixture

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


class TestInventoryLoading(unittest.TestCase):
    def test_load_inventory_skips_incomplete_rows(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "assets.csv"
            path.write_text(
                "host,vendor,product,version\n"
                "WS-01,apache,log4j,2.14.0\n"
                "WS-02,apache,,2.4.49\n",
                encoding="utf-8",
            )

            assets = load_inventory_from_csv(path)

        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].host, "WS-01")

    def test_load_inventory_rejects_missing_columns(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "assets.csv"
            path.write_text("host,vendor,product\nWS-01,apache,log4j\n", encoding="utf-8")

            with self.assertRaises(ValueError):
                load_inventory_from_csv(path)


class TestCliParser(unittest.TestCase):
    def test_threshold_accepts_valid_cvss_score(self):
        parser = _build_parser()
        args = parser.parse_args(["--threshold", "7.5", "--dry-run"])
        self.assertEqual(args.threshold, 7.5)

    def test_threshold_rejects_out_of_range_score(self):
        parser = _build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["--threshold", "11"])


class PagingNVDClient(NVDClient):
    def __init__(self, pages):
        super().__init__(max_results=1)
        self.pages = list(pages)
        self.start_indexes = []

    async def _fetch_page_with_retry(self, asset, cpe, params):
        self.start_indexes.append(params["startIndex"])
        return self.pages.pop(0)


def _nvd_page(cve_id, total_results, results_per_page=1):
    return {
        "resultsPerPage": results_per_page,
        "startIndex": 0,
        "totalResults": total_results,
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "descriptions": [{"lang": "en", "value": f"{cve_id} description"}],
                    "published": "2024-01-01T00:00:00.000",
                    "lastModified": "2024-01-02T00:00:00.000",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                }
                            }
                        ]
                    },
                }
            }
        ],
    }


class TestNVDClient(unittest.IsolatedAsyncioTestCase):
    async def test_fetch_with_retry_reads_all_pages(self):
        asset = SoftwareAsset(
            host="WS-01", vendor="apache", product="log4j", version="2.14.0",
            reviewed_cpe="cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*",
            mapping_source="NVD CPE Dictionary review",
        )
        client = PagingNVDClient(
            pages=[
                _nvd_page("CVE-2024-0001", total_results=2),
                _nvd_page("CVE-2024-0002", total_results=2),
            ]
        )

        records = await client._fetch_with_retry(asset)

        self.assertEqual(client.start_indexes, [0, 1])
        self.assertEqual([r.cve_id for r in records], ["CVE-2024-0001", "CVE-2024-0002"])

    async def test_fetch_with_retry_deduplicates_cves(self):
        asset = SoftwareAsset(
            host="WS-01", vendor="apache", product="log4j", version="2.14.0",
            reviewed_cpe="cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*",
            mapping_source="NVD CPE Dictionary review",
        )
        client = PagingNVDClient(
            pages=[
                _nvd_page("CVE-2024-0001", total_results=2),
                _nvd_page("CVE-2024-0001", total_results=2),
            ]
        )

        records = await client._fetch_with_retry(asset)

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].cve_id, "CVE-2024-0001")

    async def test_unresolved_mapping_never_produces_cves(self):
        asset = SoftwareAsset(host="WS-02", vendor="Unknown", product="Tool", version="1")
        client = PagingNVDClient(pages=[_nvd_page("CVE-2024-9999", total_results=1)])
        records = await client._fetch_with_retry(asset)
        self.assertEqual(records, [])
        self.assertEqual(client.start_indexes, [])

    def test_retry_after_controls_retryable_delay(self):
        self.assertEqual(NVDClient._retry_delay(0, "17"), 17.0)


class TestMappingBoundary(unittest.TestCase):
    def test_explicit_valid_cpe_is_matched(self):
        asset = SoftwareAsset(
            host="LAB-01", vendor="Apache", product="Log4j", version="2.14.0",
            reviewed_cpe="cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*",
            mapping_source="NVD CPE Dictionary review",
        )
        self.assertEqual(asset.mapping_status, "matched")

    def test_unresolved_product_stays_unresolved(self):
        self.assertEqual(SoftwareAsset("LAB-01", "Unknown", "Tool", "1").mapping_status, "unresolved")

    def test_multiple_candidates_are_ambiguous(self):
        asset = SoftwareAsset(
            "LAB-01", "Example", "Agent", "2",
            candidate_cpes=(
                "cpe:2.3:a:example:agent:2:*:*:*:*:*:*:*",
                "cpe:2.3:a:example:agent_pro:2:*:*:*:*:*:*:*",
            ),
        )
        self.assertEqual(asset.mapping_status, "ambiguous")


class TestRecordedFixtures(unittest.TestCase):
    fixture_dir = Path(__file__).parent / "fixtures"

    def test_recorded_nvd_fixture_parses(self):
        payload = load_recorded_fixture(
            self.fixture_dir / "nvd_cve_page.json", today=date(2026, 8, 31)
        )
        asset = SoftwareAsset("LAB", "Apache", "Log4j", "2.14.0")
        records = NVDClient._parse_response(payload, asset)
        self.assertEqual([record.cve_id for record in records], ["CVE-2021-44228"])

    def test_kev_fixture_preserves_entry_due_date(self):
        payload = load_recorded_fixture(
            self.fixture_dir / "cisa_kev.json", today=date(2026, 8, 31)
        )
        entry = KEVCatalog.from_payload(payload).lookup("CVE-2021-44228")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.due_date, "2021-12-24")

    def test_stale_fixture_is_rejected(self):
        with self.assertRaises(RecordedFixtureError):
            load_recorded_fixture(
                self.fixture_dir / "nvd_cve_page.json",
                today=date(2030, 1, 1), max_age_days=365,
            )

    def test_malformed_fixture_is_rejected(self):
        with self.assertRaises(RecordedFixtureError):
            load_recorded_fixture(self.fixture_dir / "malformed.json")


class TestPolicyWording(unittest.TestCase):
    def test_non_fceb_wording_is_explicit(self):
        from scanner import report
        import inspect
        text = inspect.getsource(report._build_kev_section)
        self.assertIn("federal civilian executive branch", text)
        self.assertIn("prioritization guidance", text)

    def test_configurable_organizational_target(self):
        asset = SoftwareAsset("LAB", "Vendor", "Product", "1")
        cve = CVERecord("CVE-1", "x", 9.8, "CRITICAL", "N/A", "3.1", "2026-01-01", "2026-01-01", asset)
        self.assertEqual(cve.target_days({"CRITICAL": 7}), 7)

if __name__ == '__main__':
    unittest.main()
