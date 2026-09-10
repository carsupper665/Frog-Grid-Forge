## ADDED Requirements
### Requirement: UserInfo permission level
The UserInfo endpoint SHALL report the subject's current permission level, read from storage rather than from the presented token.
#### Scenario: Valid access token
- **WHEN** a relying party calls GET /x/userinfo with a valid access token carrying the openid scope
- **THEN** the response SHALL include a role field holding the subject's stored permission level.
#### Scenario: Level changed after the token was issued
- **WHEN** the subject's permission level changes after the access token was issued
- **THEN** UserInfo SHALL report the new level, because access and ID tokens carry no permission claim.
