## ADDED Requirements
### Requirement: Password Reset via Email Token
FGF-idP SHALL allow users to trigger and complete password reset using signed, time-limited tokens delivered via email without leaking account existence.

#### Scenario: Request reset with email
- **WHEN** a user submits a valid email or username to POST `/x/forgot-password`
- **THEN** the system SHALL generate a one-time reset token bound to the account and expiration, store a hashed reference, send it via configured SMTP, and respond `202` without confirming account presence.

#### Scenario: Reset with valid token
- **WHEN** a user calls POST `/x/reset-password` with a valid reset token and a compliant new password
- **THEN** the system SHALL validate the token, update the password hash, invalidate existing login cookies/authorization cache, and respond `200`.

#### Scenario: Expired or reused token
- **WHEN** the reset token is expired, revoked, or already used
- **THEN** the system SHALL reject the request with `400`/`410`, leave the stored password unchanged, and log a security event.

#### Scenario: Throttled requests
- **WHEN** repeated reset requests exceed rate limits for the same IP/user/email
- **THEN** the system SHALL respond `429` and SHALL NOT send additional reset emails.
