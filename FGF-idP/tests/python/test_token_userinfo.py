"""Token exchange and userinfo endpoint tests."""

from __future__ import annotations

import unittest
from typing import Optional

import requests

from .client import FGFTestClient


class TokenUserInfoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client = FGFTestClient()

    def _skip_if_unreachable(self, error: Exception) -> None:
        self.skipTest(f"Service unreachable: {error}")

    def test_userinfo_without_token_returns_401(self) -> None:
        try:
            resp = self.client.get("/x/userinfo", allow_redirects=False)
        except requests.exceptions.RequestException as err:
            return self._skip_if_unreachable(err)

        self.assertEqual(resp.status, 401, msg=f"expected 401, got {resp.status}")
        self.assertIn("WWW-Authenticate", resp.headers)
        self.assertEqual(resp.headers.get("WWW-Authenticate"), 'Bearer error="invalid_token"')

    def test_userinfo_with_invalid_token_returns_401(self) -> None:
        try:
            resp = self.client.get(
                "/x/userinfo",
                allow_redirects=False,
                headers={"Authorization": "Bearer invalid-token"},
            )
        except requests.exceptions.RequestException as err:
            return self._skip_if_unreachable(err)

        self.assertEqual(resp.status, 401, msg=f"expected 401, got {resp.status}")
        self.assertEqual(resp.headers.get("WWW-Authenticate"), 'Bearer error="invalid_token"')

    def test_userinfo_with_valid_token_returns_claims(self) -> None:
        cfg = self.client.config
        if not cfg.prebuilt_access_token:
            self.skipTest("TEST_ACCESS_TOKEN not provided; supply a valid access token to run this test.")
        try:
            resp = self.client.get(
                "/x/userinfo",
                allow_redirects=False,
                headers={"Authorization": f"Bearer {cfg.prebuilt_access_token}"},
            )
        except requests.exceptions.RequestException as err:
            return self._skip_if_unreachable(err)

        self.assertEqual(resp.status, 200, msg=f"expected 200, got {resp.status} body={resp.text}")
        data = resp.json_body or {}
        for key in ("sub", "email", "name"):
            self.assertIn(key, data)

    def test_token_rejects_unsupported_grant_type(self) -> None:
        cfg = self.client.config
        form = {
            "grant_type": "client_credentials",
            "code": "unused",
            "redirect_uri": cfg.redirect_uri,
            "client_id": cfg.client_id,
            "client_secret": cfg.client_secret,
        }
        try:
            resp = self.client.post_form("/x/token", form, allow_redirects=False)
        except requests.exceptions.RequestException as err:
            return self._skip_if_unreachable(err)

        self.assertEqual(resp.status, 400, msg=f"expected 400, got {resp.status}")
        self.assertEqual((resp.json_body or {}).get("error"), "unsupported_grant_type")

    def test_token_exchange_requires_valid_code(self) -> None:
        cfg = self.client.config
        if not cfg.prebuilt_auth_code:
            self.skipTest("TEST_AUTH_CODE not provided; supply a valid code to run this test.")
        form = {
            "grant_type": "authorization_code",
            "code": cfg.prebuilt_auth_code,
            "redirect_uri": cfg.redirect_uri,
            "client_id": cfg.client_id,
            "client_secret": cfg.client_secret,
        }
        try:
            resp = self.client.post_form("/x/token", form, allow_redirects=False)
        except requests.exceptions.RequestException as err:
            return self._skip_if_unreachable(err)

        self.assertEqual(resp.status, 200, msg=f"expected 200, got {resp.status} body={resp.text}")
        data: Optional[dict] = resp.json_body
        self.assertIsInstance(data, dict)
        for key in ("access_token", "id_token", "token_type", "expires_in", "scope"):
            self.assertIn(key, data)
        self.assertNotIn("refresh_token", data)


if __name__ == "__main__":
    unittest.main()
