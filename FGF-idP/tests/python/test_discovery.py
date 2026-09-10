"""Discovery and JWKS endpoint tests."""

from __future__ import annotations

import unittest
from urllib.parse import urlparse

import requests

from .client import FGFTestClient


class DiscoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client = FGFTestClient()

    def _skip_if_unreachable(self, error: Exception) -> None:
        self.skipTest(f"Service unreachable: {error}")

    def test_openid_configuration(self) -> None:
        try:
            resp = self.client.get("/.well-known/openid-configuration", allow_redirects=False)
        except requests.exceptions.RequestException as err:
            return self._skip_if_unreachable(err)

        self.assertEqual(resp.status, 200, msg=f"unexpected status {resp.status} body={resp.text}")
        self.assertIsInstance(resp.json_body, dict)
        data = resp.json_body or {}
        for key in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"):
            self.assertIn(key, data, msg=f"missing {key} in discovery")
            parsed = urlparse(data[key])
            self.assertTrue(parsed.scheme and parsed.netloc, msg=f"{key} not a full URL: {data[key]}")
        self.assertEqual(data.get("grant_types_supported"), ["authorization_code"])
        self.assertNotIn("offline_access", data.get("scopes_supported", []))

    def test_jwks_keys(self) -> None:
        try:
            resp = self.client.get("/.well-known/keys", allow_redirects=False)
        except requests.exceptions.RequestException as err:
            return self._skip_if_unreachable(err)

        self.assertEqual(resp.status, 200, msg=f"unexpected status {resp.status}")
        self.assertIsInstance(resp.json_body, dict)
        self.assertIn("keys", resp.json_body or {})


if __name__ == "__main__":
    unittest.main()
