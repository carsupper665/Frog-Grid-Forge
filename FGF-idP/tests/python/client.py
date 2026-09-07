"""HTTP client helpers for FGF-idP tests."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from http.cookiejar import Cookie, LWPCookieJar
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urljoin

import requests
from requests.structures import CaseInsensitiveDict

from .config import TestConfig


COOKIE_PATH = Path(__file__).resolve().parent / ".cli_cookies.jar"


@dataclass
class ResponseInfo:
    status: int
    headers: Dict[str, Any]
    url: str
    json_body: Optional[Dict[str, Any]] = None
    text: Optional[str] = None


class FGFTestClient:
    def __init__(self, config: Optional[TestConfig] = None, *, persist_cookies: Optional[bool] = None) -> None:
        self.config = config or TestConfig.load()
        self.session = requests.Session()
        if persist_cookies is None:
            persist_cookies = os.environ.get("FGF_TEST_PERSIST_COOKIES") == "true"
        self._persist_cookies = persist_cookies
        self._cookiejar = LWPCookieJar(str(COOKIE_PATH)) if persist_cookies else None
        if self._persist_cookies:
            self._load_cookies()

    def list_cookies(self) -> List[Cookie]:
        return list(self.session.cookies)

    def clear_cookies(self) -> None:
        self.session.cookies.clear()
        if not self._persist_cookies or self._cookiejar is None:
            return
        self._cookiejar.clear()
        if COOKIE_PATH.exists():
            try:
                COOKIE_PATH.unlink()
            except Exception:
                pass

    def set_cookie(self, name: str, value: str) -> None:
        self.session.cookies.set(name, value, path="/")
        self._save_cookies()

    def clear_cookie(self, name: str) -> None:
        for cookie in list(self.session.cookies):
            if cookie.name == name:
                self.session.cookies.clear(cookie.domain, cookie.path, cookie.name)
        self._save_cookies()

    def build_url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return urljoin(self.config.base_url + "/", path.lstrip("/"))

    def get(self, path: str, *, allow_redirects: bool = False, headers: Optional[Dict[str, str]] = None) -> ResponseInfo:
        url = self.build_url(path)
        resp = self.session.get(url, allow_redirects=allow_redirects, headers=headers)
        return self._wrap(resp)

    def post_json(self, path: str, payload: Dict[str, Any], *, allow_redirects: bool = False, headers: Optional[Dict[str, str]] = None) -> ResponseInfo:
        url = self.build_url(path)
        resp = self.session.post(url, json=payload, allow_redirects=allow_redirects, headers=headers)
        return self._wrap(resp)

    def post_form(self, path: str, data: Dict[str, Any], *, allow_redirects: bool = False, headers: Optional[Dict[str, str]] = None) -> ResponseInfo:
        url = self.build_url(path)
        resp = self.session.post(url, data=data, allow_redirects=allow_redirects, headers=headers)
        return self._wrap(resp)

    def auth_request(self, *, response_type: str = "code", scope: str = "openid profile", state: str = "state-123", extra: Optional[Dict[str, Any]] = None, allow_redirects: bool = False, redirect_uri: Optional[str] = None) -> ResponseInfo:
        params = {
            "response_type": response_type,
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri or self.config.redirect_uri,
            "scope": scope,
            "state": state,
        }
        if extra:
            params.update(extra)
        query = urlencode(params, doseq=True)
        path = f"/x/auth?{query}"
        return self.get(path, allow_redirects=allow_redirects)

    def _wrap(self, resp: requests.Response) -> ResponseInfo:
        json_body: Optional[Dict[str, Any]] = None
        try:
            json_body = resp.json()
        except (ValueError, json.JSONDecodeError):
            pass
        self._save_cookies()
        return ResponseInfo(
            status=resp.status_code,
            headers=CaseInsensitiveDict(resp.headers),
            url=resp.url,
            json_body=json_body,
            text=resp.text if json_body is None else None,
        )

    def _load_cookies(self) -> None:
        if self._cookiejar is None:
            return
        try:
            self._cookiejar.load(ignore_discard=True, ignore_expires=True)
        except FileNotFoundError:
            return
        except Exception:
            return
        for cookie in self._cookiejar:
            self.session.cookies.set_cookie(cookie)

    def _save_cookies(self) -> None:
        if self._cookiejar is None:
            return
        self._cookiejar.clear()
        for cookie in self.session.cookies:
            self._cookiejar.set_cookie(cookie)
        try:
            self._cookiejar.save(ignore_discard=True, ignore_expires=True)
        except Exception:
            pass
