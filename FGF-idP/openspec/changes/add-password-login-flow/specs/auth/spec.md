## ADDED Requirements
### Requirement: Password Login Session and Device Verification
FGF-idP SHALL allow a user to authenticate with username or email plus password for a pending authorization request, issue a long-lived `au4ul4` session cookie, and require a user-scoped trusted `did` device before issuing an authorization code.

#### Scenario: Trusted device login resumes authorization
- **WHEN** a valid username or email, password, and `req_id` are submitted from a device already trusted for that user
- **THEN** the system SHALL issue or refresh `au4ul4` and redirect to the original client callback with an authorization code and state.

#### Scenario: New device requires verification
- **WHEN** valid credentials are submitted without a trusted `did` for that user
- **THEN** the system SHALL issue or refresh `au4ul4`, create or reuse `did`, send a verification token, and respond `203` without issuing an authorization code.

#### Scenario: Verification trusts device and resumes authorization
- **WHEN** `/x/verify` receives a valid verification token and matching `did` cookie
- **THEN** the system SHALL save the device as trusted for that user, clear the verification token, and redirect to the original callback with an authorization code and state.

#### Scenario: Authorization uses session and trusted device
- **WHEN** `/x/auth` receives a valid `au4ul4` session and a `did` trusted for that user
- **THEN** the system SHALL issue an authorization code directly without sending the user to login.

#### Scenario: Invalid credentials do not resume authorization
- **WHEN** the username/email does not exist or the password hash comparison fails
- **THEN** the system SHALL respond with `401 invalid_credentials` and SHALL NOT issue or reuse authorization codes.

#### Scenario: Missing or expired authorization request
- **WHEN** the provided `req_id` is absent or not present in the authorization cache
- **THEN** the system SHALL respond with `400 invalid_req_id` or `400 invalid_request` and require the client to restart `/x/auth`.
