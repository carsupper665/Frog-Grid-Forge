"""Authorization endpoint flow tests."""

from __future__ import annotations

import unittest
from urllib.parse import parse_qs, urlparse

import requests

from .client import FGFTestClient


class AuthFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client = FGFTestClient()

    def _skip_if_unreachable(self, error: Exception) -> None:
        self.skipTest(f"Service unreachable: {error}")

    def test_auth_valid_request_redirects_to_login_with_req_id(self) -> None:
        try:
            resp = self.client.auth_request(allow_redirects=False)
        except requests.exceptions.RequestException as err:
            return self._skip_if_unreachable(err)

        self.assertEqual(resp.status, 302, msg=f"expected 302 redirect, got {resp.status}")
        location = resp.headers.get("Location") or resp.url
        parsed = urlparse(location)
        self.assertEqual(parsed.path, "/login")
        query = parse_qs(parsed.query)
        self.assertIn("req_id", query)
        self.assertTrue(query["req_id"][0])

    def test_auth_rejects_unregistered_redirect(self) -> None:
        try:
            resp = self.client.auth_request(
                redirect_uri="http://evil.example.com/callback",
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as err:
            return self._skip_if_unreachable(err)

        self.assertEqual(resp.status, 400, msg=f"expected 400 JSON, got {resp.status}")
        if resp.json_body is not None:
            self.assertIn("error", resp.json_body)

    def test_auth_unsupported_response_type_redirects_with_state(self) -> None:
        state = "test-state-123"
        try:
            resp = self.client.auth_request(
                response_type="token",
                state=state,
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as err:
            return self._skip_if_unreachable(err)

        self.assertEqual(resp.status, 302, msg=f"expected 302 redirect, got {resp.status}")
        location = resp.headers.get("Location") or resp.url
        parsed = urlparse(location)
        self.assertTrue(parsed.scheme and parsed.netloc, msg="redirect missing host")
        query = parse_qs(parsed.query)
        self.assertEqual(query.get("error"), ["unsupported_response_type"])
        self.assertEqual(query.get("state"), [state])

    def test_auth_invalid_scope_redirects_with_state(self) -> None:
        state = "test-invalid-scope"
        try:
            resp = self.client.auth_request(
                scope="profile email",
                state=state,
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as err:
            return self._skip_if_unreachable(err)

        self.assertEqual(resp.status, 302, msg=f"expected 302 redirect, got {resp.status}")
        location = resp.headers.get("Location") or resp.url
        parsed = urlparse(location)
        query = parse_qs(parsed.query)
        self.assertEqual(query.get("error"), ["invalid_scope"])
        self.assertEqual(query.get("state"), [state])


if __name__ == "__main__":
    unittest.main()
