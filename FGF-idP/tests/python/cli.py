"""Simple CLI to exercise FGF-idP endpoints with cookie support."""

from __future__ import annotations

import argparse
import json
import sys
from getpass import getpass
from typing import Any, Dict, Optional

import requests

from .client import FGFTestClient
from .config import TestConfig


def _print_response(label: str, resp) -> None:
    print(f"[{label}] status={resp.status}")
    for k, v in resp.headers.items():
        print(f"  {k}: {v}")
    if resp.json_body is not None:
        print(json.dumps(resp.json_body, indent=2, ensure_ascii=False))
    elif resp.text:
        print(resp.text)


def cmd_discovery(client: FGFTestClient, args: argparse.Namespace) -> None:
    resp = client.get("/.well-known/openid-configuration", allow_redirects=False)
    _print_response("discovery", resp)


def cmd_keys(client: FGFTestClient, args: argparse.Namespace) -> None:
    resp = client.get("/.well-known/keys", allow_redirects=False)
    _print_response("jwks", resp)


def cmd_auth(client: FGFTestClient, args: argparse.Namespace) -> None:
    extra: Dict[str, Any] = {}
    if args.code_challenge:
        extra["code_challenge"] = args.code_challenge
    if args.code_challenge_method:
        extra["code_challenge_method"] = args.code_challenge_method

    resp = client.auth_request(
        response_type=args.response_type,
        scope=args.scope,
        state=args.state,
        redirect_uri=args.redirect_uri,
        allow_redirects=False,
        extra=extra if extra else None,
    )
    _print_response("auth", resp)


def cmd_token(client: FGFTestClient, args: argparse.Namespace) -> None:
    cfg = client.config
    code = args.code or cfg.prebuilt_auth_code
    if not code:
        code = input("authorization code: ").strip()
    client_secret = args.client_secret or cfg.client_secret
    if client_secret == "" and args.prompt_secret:
        client_secret = getpass("client_secret: ")

    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": args.redirect_uri or cfg.redirect_uri,
        "client_id": args.client_id or cfg.client_id,
        "client_secret": client_secret,
    }
    resp = client.post_form("/x/token", form, allow_redirects=False)
    _print_response("token", resp)


def cmd_userinfo(client: FGFTestClient, args: argparse.Namespace) -> None:
    bearer = args.bearer or client.config.prebuilt_access_token
    headers: Optional[Dict[str, str]] = None
    if bearer:
        headers = {"Authorization": f"Bearer {bearer}"}
    resp = client.get("/x/userinfo", allow_redirects=False, headers=headers)
    _print_response("userinfo", resp)


def cmd_cookies(client: FGFTestClient, args: argparse.Namespace) -> None:
    if args.clear:
        client.clear_cookies()
        print("[cookies] cleared")
        return
    cookies = client.list_cookies()
    if not cookies:
        print("[cookies] no stored cookies")
        return
    for cookie in cookies:
        print(f"{cookie.name}={cookie.value}; domain={cookie.domain}; path={cookie.path}")

def cmd_get(client: FGFTestClient, args: argparse.Namespace) -> None:
    resp = client.get(args.path, allow_redirects=True)
    _print_response("get", resp)

def cmd_login(client: FGFTestClient, args: argparse.Namespace) -> None:
    password = args.password
    if not password:
        password = getpass("password: ")

    form = {}
    if args.email and not args.username:
        form["email"] = args.email
    if args.username and not args.email:
        form["username"] = args.username
    if args.username and args.email:
        form["username"] = args.username
    form["password"] = password
    form["req_id"] = args.reqid

    resp = client.post_json(f"/x/login", form, allow_redirects=False)
    _print_response("login", resp)

def gen_hash(password: str) -> str:
    """Generate a bcrypt hash for the given password."""
    import bcrypt

    salt = bcrypt.gensalt(rounds=10)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    print(hashed.decode("utf-8"))

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="FGF-idP endpoint tester (cookie-aware).")
    parser.add_argument("--base-url", help="override base URL (default from env/.env)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("discovery", help="GET /.well-known/openid-configuration")
    sub.add_parser("keys", help="GET /.well-known/keys")

    pa = sub.add_parser("auth", help="Call /x/auth")
    pa.add_argument("--response-type", default="code")
    pa.add_argument("--scope", default="openid profile")
    pa.add_argument("--state", default="cli-state-test")
    pa.add_argument("--redirect-uri", help="override redirect_uri")
    pa.add_argument("--code-challenge")
    pa.add_argument("--code-challenge-method", choices=["S256", "plain"])

    pt = sub.add_parser("token", help="Exchange /x/token")
    pt.add_argument("--code", help="authorization code")
    pt.add_argument("--redirect-uri", help="override redirect_uri")
    pt.add_argument("--client-id", help="override client_id", default="fgf-mc-panel")   
    pt.add_argument("--client-secret", help="override client_secret", default="123456")
    pt.add_argument("--prompt-secret", action="store_true", help="prompt for client_secret if empty")

    pu = sub.add_parser("userinfo", help="Call /x/userinfo")
    pu.add_argument("--bearer", help="access token")

    pc = sub.add_parser("cookies", help="Inspect or clear stored cookies")
    pc.add_argument("--clear", action="store_true", help="drop all cookies before exiting")

    login = sub.add_parser("login")
    login.add_argument("--username", help="username", type=str)
    login.add_argument("--email", help="email", type=str)
    login.add_argument("--reqid", required=True, help="request id", type=str)
    login.add_argument("--password", help="password (will prompt if not given)", type=str)

    gen_hash_parser = sub.add_parser("gen-hash", help="Generate bcrypt hash for a password")
    gen_hash_parser.add_argument("password", help="password to hash", type=str)
    get = sub.add_parser("get", help="Make a GET request to the given path")
    get.add_argument("--path", help="path to GET", type=str)

    return parser

# $2a$10$IKrvY/.OwQMGEQE2u8dAtubgO/PhdDFkuartUc7PlqnKl5jNK1ceq  123456BoNk6o2p3kQm6nHN
def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    cfg = TestConfig.load()
    if args.base_url:
        cfg.base_url = args.base_url.rstrip("/")

    client = FGFTestClient(cfg, persist_cookies=True)

    comd_direct = {
        "discovery": cmd_discovery,
        "keys": cmd_keys,
        "login": cmd_login,
        "auth": cmd_auth,
        "token": cmd_token,
        "userinfo": cmd_userinfo,
        "cookies": cmd_cookies,
        "gen-hash": lambda c, a: gen_hash(a.password),
        "get": cmd_get,
    }

    try:
        cmd = comd_direct.get(args.cmd)
        cmd(client, args)  # type: ignore
    except requests.exceptions.RequestException as err:
        print(f"[error] request failed: {err}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
