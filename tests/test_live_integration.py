"""Opt-in live checks; ordinary CI never depends on NVD/CISA availability."""

import os
import unittest

import aiohttp

from scanner.cisa_kev import KEVCatalog


@unittest.skipUnless(os.environ.get("RUN_LIVE_NVD_TESTS") == "1", "set RUN_LIVE_NVD_TESTS=1 to opt in")
class LiveIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_cisa_catalog_is_parseable(self):
        async with aiohttp.ClientSession() as session:
            catalog = await KEVCatalog.fetch(session)
        self.assertNotEqual(catalog.catalog_version, "unavailable")
        self.assertGreater(catalog.total_entries, 0)
