## ADDED Requirements
### Requirement: Complete user CRUD
The admin console SHALL support creation, listing, inspection, profile editing, role updates and soft deletion without exposing credential material.
#### Scenario: Create
- **WHEN** an administrator submits a unique valid username/email and an initial password
- **THEN** the service SHALL store a salted password hash and grant only a role below the caller's role.
#### Scenario: Edit
- **WHEN** an administrator edits a lower-privilege user's username, display name or email
- **THEN** valid changes SHALL persist without changing the user's ID or role.
#### Scenario: Protected account
- **WHEN** an administrator targets themselves, a peer, a superior or a root account
- **THEN** the mutation SHALL fail with 403.
#### Scenario: Conflict
- **WHEN** username or email conflicts with another account, including a deleted account
- **THEN** the service SHALL reject the write with 409.
#### Scenario: Email update
- **WHEN** the email changes
- **THEN** trusted devices, pending email bindings and authorization codes for that user SHALL be invalidated, and an old link SHALL NOT authenticate another user of the old email.
#### Scenario: UI operations
- **WHEN** the administrator creates, edits or deletes a user
- **THEN** the list SHALL reflect persisted data and display retryable errors.
