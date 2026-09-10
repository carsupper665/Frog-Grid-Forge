## ADDED Requirements
### Requirement: User directory
The service SHALL let a caller at RoleAdminUser or above list, search and page through accounts, change a permission level, and soft delete an account, without exposing credential material.
#### Scenario: Listing accounts
- **WHEN** a caller at RoleAdminUser requests the user directory
- **THEN** the response SHALL contain only identity and permission fields and SHALL NOT contain a password hash, a salt or an access token.
#### Scenario: Searching accounts
- **WHEN** a search term contains LIKE wildcard characters
- **THEN** they SHALL be matched literally rather than as pattern operators.
#### Scenario: Deleting an account
- **WHEN** an authorized caller deletes an account
- **THEN** the account SHALL be soft deleted and its outstanding sessions SHALL stop working on their next request.

### Requirement: Privilege escalation guards
The admin API SHALL reject any change whose effect would raise the caller's own standing, alter a peer or superior, or touch a root account.
#### Scenario: Acting on oneself
- **WHEN** a caller requests a role change or deletion of their own account
- **THEN** the service SHALL respond 403 and leave the account unchanged.
#### Scenario: Root account is immutable
- **WHEN** any caller requests a role change or deletion of an account whose role is RoleRootUser
- **THEN** the service SHALL respond 403.
#### Scenario: Acting on a peer or superior
- **WHEN** a caller targets an account whose stored role is greater than or equal to their own
- **THEN** the service SHALL respond 403.
#### Scenario: Granting at or above own level
- **WHEN** a caller requests a role greater than or equal to their own stored level
- **THEN** the service SHALL respond 403 and leave the target unchanged.
#### Scenario: Unknown permission level
- **WHEN** a role change names a level that is not defined
- **THEN** the service SHALL respond 400; a request naming RoleGuestUser SHALL be accepted.

### Requirement: OAuth client management
The service SHALL let a caller at RoleRootUser register, inspect, update and soft delete OAuth clients, and SHALL disclose a generated client secret exactly once.
#### Scenario: Below the service threshold
- **WHEN** a caller at RoleAdminUser requests any client management endpoint
- **THEN** the service SHALL respond 403.
#### Scenario: Registering a client
- **WHEN** a root caller registers a client
- **THEN** the service SHALL generate a secret, store only its hash, and return the plaintext in that response alone.
#### Scenario: Reading a client
- **WHEN** any client is listed or fetched
- **THEN** the response SHALL NOT contain the secret or its hash.
#### Scenario: Rotating a secret
- **WHEN** a root caller rotates a client secret
- **THEN** the previous secret SHALL stop authenticating that client and the new secret SHALL authenticate it.
#### Scenario: Deleting a client
- **WHEN** a root caller deletes a client
- **THEN** the client SHALL immediately stop passing authorization and token validation.

### Requirement: Redirect URI validation
The service SHALL only register redirect URIs that cannot be used to divert authorization codes, and SHALL store them for exact comparison.
#### Scenario: Unsafe redirect URI
- **WHEN** a redirect URI is relative, has no host, uses a scheme other than http or https, contains a fragment, or contains a wildcard
- **THEN** the service SHALL reject the registration with 400.
#### Scenario: Plaintext transport outside debug mode
- **WHEN** an http redirect URI is registered outside debug mode for a host that is not a loopback address
- **THEN** the service SHALL reject the registration with 400.
#### Scenario: Stored form
- **WHEN** redirect URIs are accepted
- **THEN** they SHALL be stored trimmed and de-duplicated but otherwise unmodified, so comparison at authorization time remains exact.

### Requirement: Embedded admin console
The service SHALL serve an admin console from its Go executable under the same strict content security policy as the login page.
#### Scenario: Console shell
- **WHEN** a browser requests /admin
- **THEN** the service SHALL return the embedded page with a no-store cache directive and a content security policy that forbids inline script and framing.
#### Scenario: Unauthenticated console
- **WHEN** the console loads without a valid session
- **THEN** it SHALL present the administrator sign-in form rather than an empty directory.
#### Scenario: Console asset boundary
- **WHEN** a request targets a path outside the embedded page and asset directories, including a traversal attempt
- **THEN** the service SHALL respond 404.
