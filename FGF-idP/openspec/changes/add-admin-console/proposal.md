## Why
The User.Role column and its permission constants already exist but nothing reads them: no claim, no middleware, no endpoint, and GetRole had zero callers. OAuth clients could only be created by a hardcoded startup seed. Operators had no way to grant or revoke administrator access, and no way to register a service.

## What Changes
- Enforce the stored permission level on every request with a RequireRole middleware that reads the level from the database rather than from any cached or client-supplied value.
- Add an admin console at /admin with its own sign-in, independent of the OAuth authorization flow.
- Add a user directory with role changes and soft deletion, gated at RoleAdminUser and guarded against privilege escalation.
- Add OAuth client management with redirect URI validation and one-time secrets, gated at RoleRootUser.
- Return the permission level from /x/userinfo.
- Honour the redirect URI verdict in ValiClient, which was previously overwritten by the secret check.

## Impact
- Affected specs: admin, auth, oidc
- Affected code: common constants, model user/client/token/query, middleware, controller admin handlers, router, embedded frontend
- Approval: user explicitly requested this plan in the conversation, including the dedicated root sign-in entrance.
