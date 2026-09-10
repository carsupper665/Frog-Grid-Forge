## Why
Replace the development-only login experience with the user-approved 2a forest/glass production page.

## What Changes
- Embed a vanilla same-origin login UI in Go and preserve the separate web tester.
- Add opt-in JSON login redirects and browser-friendly verification errors.
- Cover responsive UI and existing authentication behavior with regression tests.

## Impact
- Affected specs: login
- Affected code: frontend, router, controller login and verification
- Approval: user explicitly requested implementation of this plan in the conversation.
