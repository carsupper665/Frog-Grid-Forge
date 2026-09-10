## ADDED Requirements
### Requirement: Administrator sign-in
The service SHALL provide an administrator sign-in that does not depend on a registered OAuth client, and SHALL make its failure modes indistinguishable.
#### Scenario: Valid administrator credentials
- **WHEN** POST /x/admin/login receives a JSON account and password for an account whose stored role is at least RoleAdminUser
- **THEN** the service SHALL issue a session cookie and return the caller id, username and role.
#### Scenario: Rejected sign-in
- **WHEN** the account does not exist, the password is wrong, or the stored role is below RoleAdminUser
- **THEN** the service SHALL return an identical 401 invalid_credentials response in all three cases and SHALL NOT issue a session cookie.

### Requirement: Role based route protection
The service SHALL gate protected routes on the permission level stored for the caller, read at request time rather than taken from the session token or any cache.
#### Scenario: Insufficient level
- **WHEN** an authenticated caller whose stored role is below the route threshold makes a request
- **THEN** the service SHALL respond 403 and SHALL NOT run the handler.
#### Scenario: Level changed after sign-in
- **WHEN** a caller is demoted or soft deleted while holding an unexpired session cookie
- **THEN** the next request using that cookie SHALL be rejected, without requiring the cookie to be revoked.
#### Scenario: Permission store unavailable
- **WHEN** the permission level cannot be read because storage failed
- **THEN** the service SHALL respond 503 rather than treating the caller as unauthorized or authorized.
