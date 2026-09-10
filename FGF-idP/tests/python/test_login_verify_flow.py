"""Login and verify endpoint tests."""

from __future__ import annotations

import unittest
from urllib.parse import parse_qs, urlparse

import requests

from .client import FGFTestClient


class LoginVerifyFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client = FGFTestClient()

    def _skip_if_unreachable(self, error: Exception) -> None:
        self.skipTest(f"Service unreachable: {error}")

    def _start_auth_req_id(self) -> str:
        resp = self.client.auth_request(allow_redirects=False)
        self.assertEqual(resp.status, 302, msg=f"expected 302, got {resp.status}")
        query = parse_qs(urlparse(resp.headers.get("Location") or resp.url).query)
        req_id = (query.get("req_id") or [""])[0]
        self.assertTrue(req_id, msg="auth redirect missing req_id")
        return req_id

    def test_login_missing_req_id_returns_400(self) -> None:
        try:
            resp = self.client.post_json(
                "/x/login",
                {"username": "nobody", "password": "bad-password"},
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as err:
            return self._skip_if_unreachable(err)

        self.assertEqual(resp.status, 400, msg=f"expected 400, got {resp.status}")
        self.assertEqual((resp.json_body or {}).get("error"), "invalid_request")

    def test_login_invalid_req_id_returns_400(self) -> None:
        try:
            resp = self.client.post_json(
                "/x/login",
                {"username": "nobody", "password": "bad-password", "req_id": "missing-req"},
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as err:
            return self._skip_if_unreachable(err)

        self.assertEqual(resp.status, 400, msg=f"expected 400, got {resp.status}")
        self.assertEqual((resp.json_body or {}).get("error"), "invalid_req_id")

    def test_login_wrong_password_returns_401(self) -> None:
        cfg = self.client.config
        if not cfg.username:
            self.skipTest("TEST_USERNAME not provided; cannot run wrong-password test.")
        try:
            req_id = self._start_auth_req_id()
            resp = self.client.post_json(
                "/x/login",
                {"username": cfg.username, "password": "definitely-wrong-password", "req_id": req_id},
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as err:
            return self._skip_if_unreachable(err)

        self.assertEqual(resp.status, 401, msg=f"expected 401, got {resp.status}")
        self.assertEqual((resp.json_body or {}).get("error"), "invalid_credentials")

    def test_login_untrusted_device_returns_203(self) -> None:
        cfg = self.client.config
        if not cfg.username or not cfg.password:
            self.skipTest("TEST_USERNAME/TEST_PASSWORD not provided; cannot run login happy-path test.")
        try:
            self.client.clear_cookies()
            self.client.set_cookie("did", "python-untrusted-device")
            req_id = self._start_auth_req_id()
            resp = self.client.post_json(
                "/x/login",
                {"username": cfg.username, "password": cfg.password, "req_id": req_id},
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as err:
            return self._skip_if_unreachable(err)

        self.assertEqual(resp.status, 203, msg=f"expected 203, got {resp.status} body={resp.text}")
        self.assertEqual((resp.json_body or {}).get("email") is not None, True)

    def test_verify_missing_token_returns_400(self) -> None:
        try:
            resp = self.client.get("/x/verify", allow_redirects=False)
        except requests.exceptions.RequestException as err:
            return self._skip_if_unreachable(err)

        self.assertEqual(resp.status, 400, msg=f"expected 400, got {resp.status}")
        self.assertEqual((resp.json_body or {}).get("error"), "missing_token")

    def test_verify_invalid_token_returns_400(self) -> None:
        try:
            resp = self.client.get("/x/verify?t=not-a-valid-token", allow_redirects=False)
        except requests.exceptions.RequestException as err:
            return self._skip_if_unreachable(err)

        self.assertEqual(resp.status, 400, msg=f"expected 400, got {resp.status}")
        self.assertIn((resp.json_body or {}).get("error"), {"invalid_token", "invalid_req_id", "missing_device_cookie", "expired_token"})

    def test_verify_success_smoke_with_prebuilt_token(self) -> None:
        cfg = self.client.config
        if not cfg.prebuilt_verify_token:
            self.skipTest("TEST_VERIFY_TOKEN not provided; cannot run verify success smoke.")
        try:
            resp = self.client.get(f"/x/verify?t={cfg.prebuilt_verify_token}", allow_redirects=False)
        except requests.exceptions.RequestException as err:
            return self._skip_if_unreachable(err)

        self.assertEqual(resp.status, 302, msg=f"expected 302, got {resp.status} body={resp.text}")


if __name__ == "__main__":
    unittest.main()
