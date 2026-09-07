## ADDED Requirements
### Requirement: Python unittest HTTP harness
FGF-idP SHALL provide a Python `unittest`-based harness with modular helpers to test HTTP endpoints using a cookie-aware session and configurable base URL/credentials.

#### Scenario: Session-aware client
- **WHEN** tests create the shared HTTP client
- **THEN** it SHALL reuse a `requests.Session` (or equivalent) that preserves cookies across requests and allows overriding base URL, client_id, and user credentials via env/config.

### Requirement: Core endpoints have executable tests
FGF-idP SHALL include runnable test cases covering discovery, JWKS, authorization error handling, token exchange, and userinfo access.

#### Scenario: Discovery and JWKS succeed
- **WHEN** running the test suite
- **THEN** `/.well-known/openid-configuration` and `/.well-known/keys` SHALL return HTTP 200 with required fields present.

#### Scenario: Authorization flow validates redirect handling
- **WHEN** the suite exercises `/x/auth` with valid and invalid parameters
- **THEN** valid redirect URIs SHALL yield 302 with `code` or `error` plus `state`, and unregistered redirect URIs SHALL return 400 without redirect.

#### Scenario: Token and userinfo coverage
- **WHEN** exchanging a valid authorization code in tests
- **THEN** `/x/token` SHALL return access and ID tokens consumable by `/x/userinfo`, and missing/invalid bearer tokens for `/x/userinfo` SHALL respond with 401 and no claims.
