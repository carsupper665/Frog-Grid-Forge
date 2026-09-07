# Implementation Audit

這份文件只描述目前程式行為與 `openspec/changes/` 之間的落差，方便後續補 proposal、補測試或拆 commit。

## OIDC Core Compliance

對照：`openspec/changes/add-oidc-core-compliance/`

目前狀態：本輪 plan 已落地主要 OIDC core gap。

- `/.well-known/openid-configuration` 與 `/.well-known/keys` 路由已存在。
- metadata 內容來自 `model.InitDB()` 依 `BACKEND_BASE_URL` 組出，基本端點可用。
- `/x/auth` 對 `response_type!=code` 與 `invalid_scope` 會在合法 redirect URI 下 302 帶 `error/state`。
- `/x/token` 會回 `access_token`、`id_token`、`token_type`、`expires_in`、`scope`，不再回 `refresh_token: null`。
- `/x/userinfo` 會回 `sub/email/name/preferred_username`，invalid bearer 會帶 `WWW-Authenticate: Bearer error="invalid_token"`。
- access token 與 ID token JWT header 會寫入 active `kid`。
- Discovery 已移除未支援的 `refresh_token` 與 `offline_access` 宣告。

## Password Login Flow

對照：`openspec/changes/add-password-login-flow/`

目前狀態：本輪 plan 已落地主要 password login/session/device 流程。

- `POST /x/login` 已存在，支援 `username` 或 `email` 加 `password` 與 `req_id`。
- handler 會從 auth cache 取回 `req_id`，並驗證密碼與裝置狀態。
- `/x/login` 帳密成功會簽發或刷新 `au4ul4` session cookie。
- 已信任裝置可直接簽發 authorization code 並重導回 `redirect_uri`。
- 新裝置或既有未信任裝置會回 `203` 並要求走 email verification。
- `/x/auth` 只有 `session 有效 + trusted device` 才會直接簽發 code；不可信裝置會導 login 並帶 `reason=device_verification_required`。
- `GET /x/login` 會導向前端 login route。

## Password Reset Flow

對照：`openspec/changes/add-password-reset-flow/`

目前狀態：本輪明確不實作。

- router 尚未註冊 `/x/forgot-password` 或 `/x/reset-password`。
- controller 與測試也尚未建立對應流程。

## Testing Harness

對照：`openspec/changes/add-python-unittest-harness/`

目前狀態：已更新為本輪 session/device/OIDC core 契約。

- `tests/python/` 已具備 `client.py`、`config.py`、`cli.py` 與 discovery/auth/token/userinfo 測試。
- 目前已能固定用 `python -m tests.python` 執行整個 suite。
- Python 測試覆蓋 login redirect、invalid scope redirect、wrong password、untrusted device `203`、token response scope/no refresh token、userinfo invalid header 與可選正向 smoke。
- Go handler 測試覆蓋 `/x/auth` session/trusted-device 分流、`/x/login` session cookie 與 device 分流、`/x/verify` trusted device 建立、token `kid`、userinfo claims。

## Deferred / Non-goals

- Refresh token 不做，discovery 不宣告。
- Password reset 不做，`openspec/changes/add-password-reset-flow` 應維持 defer/cancel 狀態。
- Auth request / auth code 仍為 in-memory cache，單節點限制保留。
