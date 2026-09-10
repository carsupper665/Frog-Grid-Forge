## Why
The admin console lacks user creation and profile editing.

## What Changes
Add create/read/profile-update endpoints and a shared embedded user form. Preserve role/delete guards. Bind email verification to a user ID and clear trust on email changes.

## Impact
The user requested completing user CRUD in this conversation. Scope: admin UI, controller/model/routes, verification binding and focused tests. Password reset remains in its separate existing proposal.
