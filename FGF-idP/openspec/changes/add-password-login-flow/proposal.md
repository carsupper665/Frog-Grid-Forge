## Why
- `/x/login` must resume an existing OIDC authorization request after local password authentication.
- The implementation needs a durable browser session cookie plus trusted-device verification so `/x/auth` can safely decide whether to issue an authorization code.

## What Changes
- Implement POST `/x/login` with username-or-email, password, and `req_id` validation.
- Issue or refresh the `au4ul4` HttpOnly session cookie after successful password authentication.
- Use `did` as a trusted-device cookie; untrusted devices return `203` and require email verification before becoming trusted.
- Update `/x/auth` to issue authorization codes only for `session valid + trusted device`; otherwise redirect to the frontend login route.
- Add tests for login redirects, session cookies, trusted-device branching, verification, token fields, and userinfo claims.

## Impact
- Affected specs: `auth`
- Affected code: `controller/user.go`, `model/user.go`, `common/crypto.go`, `common/constants.go`, `common/init.go`, tests and docs.
