## ADDED Requirements
### Requirement: Discovery matches issuer and endpoints
FGF-idP SHALL expose OIDC discovery at `/.well-known/openid-configuration` without a trailing slash and ensure metadata URLs (issuer, authorization, token, userinfo, end_session, jwks_uri) reflect the runtime host/port and the `/.well-known/keys` JWKS endpoint.

#### Scenario: Discovery returns correct metadata
- **WHEN** a client issues `GET /.well-known/openid-configuration`
- **THEN** the response SHALL be `200` JSON containing `issuer`, `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `end_session_endpoint`, and `jwks_uri` that match the service base URL and point to `/.well-known/keys`.

### Requirement: Authorization errors redirect per OIDC
FGF-idP SHALL redirect invalid authorization requests back to the validated `redirect_uri` with OIDC error parameters when that URI is registered; unregistered URIs SHALL be rejected without redirect.

#### Scenario: Unsupported response type
- **WHEN** a request to `/x/auth` includes an unsupported `response_type` but a registered `redirect_uri` and `state`
- **THEN** the system SHALL respond with `302` redirect to `redirect_uri` including `error=unsupported_response_type` and the original `state`.

#### Scenario: Invalid redirect URI blocked
- **WHEN** the `redirect_uri` is not registered for the client
- **THEN** the system SHALL return `400` JSON with an error and SHALL NOT redirect.

### Requirement: Token and UserInfo responses conform to OIDC
FGF-idP SHALL issue tokens and UserInfo responses that meet OIDC Core expectations for claims, headers, and error handling.

#### Scenario: Token response includes compliant claims
- **WHEN** a valid `authorization_code` exchange completes at `/x/token`
- **THEN** the access token `aud` SHALL reflect the client/resource (not the `scope`), `scope` SHALL be preserved, the ID Token SHALL include `iss`/`aud`/`sub`/`exp`/`iat` (and `nonce` if supplied), and the JWT header SHALL include the active `kid`; a `refresh_token` SHALL be returned only when `offline_access` is granted.

#### Scenario: UserInfo with bearer token
- **WHEN** a caller sends `Authorization: Bearer <access_token>` to `/x/userinfo`
- **THEN** the system SHALL return `200` with JSON containing at least `sub` and email/name claims consistent with the ID Token subject.

#### Scenario: Invalid or missing bearer token
- **WHEN** the UserInfo request lacks a valid bearer token
- **THEN** the system SHALL respond `401` with `WWW-Authenticate: Bearer error="invalid_token"` and SHALL NOT return user claims.
