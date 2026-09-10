# FGF-idP Design

## 目標

本輪目標是讓 FGF-idP 收斂到可進入生產前整備的狀態，聚焦兩個主題：

- 補完 OIDC core gap
- 定稿並實作長登入 session + trusted device + email verify 流程

## 非目標

- 不實作 password reset
- 不實作 refresh token
- 不改掉 in-memory auth request / auth code cache
- 不處理多節點共享登入流程
- 不在本輪建立完整 CI/CD 或部署系統

## 已確認決策

- `au4ul4` 是正式長登入 session cookie
- `did` 是 trusted device cookie
- email verify 是建立 trusted device 的必要條件
- `session 有效 + trusted device` 才能直接完成 `/x/auth`
- `session 有效 + device 不可信` 仍要先重新 `/x/login`
- `/x/login` 驗證密碼成功後，如果 device 不可信，才進入 email verify
- `/x/verify` 成功後，裝置才變成 trusted
- 登入畫面由前端 SPA 負責
- auth request / auth code 繼續維持 in-memory

## 流程設計

### 1. 授權入口

Client 呼叫 `GET /x/auth` 後，後端按以下順序處理：

1. 驗證 `client_id`
2. 驗證 `redirect_uri`
3. 驗證 `response_type`
4. 驗證 `scope`
5. 建立 `AuthRequest`
6. 驗證 `au4ul4`
7. 驗證 `did`
8. 決定直接發 code 或導去 login

### 2. /x/auth 分流規則

- `session 有效 + trusted device` -> 直接 `issueCodeAndRedirect`
- `session 無效` -> 302 到前端 login route，帶 `req_id`
- `session 有效 + device 不可信` -> 302 到前端 login route，帶 `req_id` 與 `reason=device_verification_required`

### 3. /x/login 分流規則

`POST /x/login` 成功驗證帳密後：

- 先簽發或刷新 `au4ul4`
- 若 `did` 已信任 -> 直接簽發 authorization code
- 若 `did` 缺失 -> 建立新 `did`，寄 verify mail，回 `203`
- 若 `did` 存在但未信任 -> 寄 verify mail，回 `203`

### 4. /x/verify 分流規則

`GET /x/verify?t=...` 成功後：

1. 驗證 email token
2. 驗證 `did` cookie
3. 找回對應 `AuthRequest`
4. 將 `did` 設為 trusted device
5. 清除 verification token
6. 保留或刷新 `au4ul4`
7. 直接簽發 code 並 redirect 回 client callback

## Cookie 與 Token 設計

### 1. au4ul4 session cookie

用途：

- 表示使用者已通過帳密驗證
- 不等同 trusted device
- 不等同 access token

建議 claims：

- `user_id`
- `username`
- `iat`
- `exp`
- `typ=session`

建議 cookie 屬性：

- `HttpOnly`
- `SameSite=Lax` 或依前端部署調整
- production 啟用 `Secure`
- 明確 TTL

### 2. did device cookie

用途：

- 標識裝置
- 對照 DB 中 trusted device 紀錄

規則：

- 沒有 `did` 時，由 `/x/login` 建立
- 只有 verify 成功後，該 `did` 才成為 trusted device

### 3. OIDC access token / id token

access token 至少包含：

- `iss`
- `sub`
- `aud`
- `scope`
- `exp`
- `iat`

id token 至少包含：

- `iss`
- `sub`
- `aud`
- `exp`
- `iat`
- `nonce` if present

兩者 JWT header 都必須包含：

- `kid`

## Endpoint 契約

### GET /x/auth

輸入：

- `response_type`
- `client_id`
- `redirect_uri`
- `scope`
- `state`
- `nonce`
- `code_challenge`
- `code_challenge_method`

成功：

- 直接授權時，302 回 client callback，帶 `code`、`state`
- 需要登入時，302 到前端 login route，帶 `req_id`

錯誤：

- `redirect_uri` 不合法 -> `400 JSON`
- `redirect_uri` 合法但授權參數錯誤 -> 302 回 `redirect_uri`，帶 `error`、`state`

### POST /x/login

輸入：

- `username` 或 `email`
- `password`
- `req_id`

成功：

- trusted device -> 302 回 callback
- untrusted device -> `203 JSON`

錯誤：

- payload 錯 -> `400 invalid_request`
- `req_id` 錯 -> `400 invalid_req_id`
- 帳密錯 -> `401 invalid_credentials`

### GET /x/verify

輸入：

- `t=<verify_token>`
- request cookie 內必須有 `did`

成功：

- 302 回 callback，帶 `code`、`state`

錯誤：

- `missing_token`
- `missing_device_cookie`
- `invalid_token`
- `invalid_req_id`
- 可選 `expired_token`

### POST /x/token

輸入：

- `grant_type=authorization_code`
- `code`
- `redirect_uri`
- `client_id`
- `client_secret`
- `code_verifier`

成功回應至少包含：

- `access_token`
- `id_token`
- `token_type`
- `expires_in`
- `scope`

錯誤：

- `invalid_request`
- `unsupported_grant_type`
- `invalid_client`
- `invalid_grant`
- `server_error`

備註：

- 本輪不回 `refresh_token`
- 不應回 `refresh_token: null`

### GET /x/userinfo

成功回應至少包含：

- `sub`
- `email`
- `name`

可選：

- `preferred_username`

錯誤：

- `401`
- `WWW-Authenticate: Bearer error="invalid_token"`

## Discovery 與 JWKS 設計

Discovery 必須與實際實作一致，至少包含：

- `issuer`
- `authorization_endpoint`
- `token_endpoint`
- `userinfo_endpoint`
- `jwks_uri`
- `end_session_endpoint`

要求：

- `issuer` 以 `BACKEND_BASE_URL` 為準
- access token / id token 的 `kid` 必須能對應 `/.well-known/keys`
- 若本輪不做 refresh token，discovery 不應宣告 `refresh_token`
- 若本輪不支援 `offline_access`，discovery 不應宣告 `offline_access`

## 資料層要求

trusted device 不應只是全域檢查 `device_id` 是否存在，而應檢查：

- 該 `device_id` 是否屬於當前 user

建議資料層抽象至少能回答：

- 這個 user 是否信任這個 device

## in-memory 限制

本輪接受以下限制：

- auth request 與 auth code 仍存記憶體
- 單實例部署較安全
- 服務重啟會使 pending auth flow 失效
- 多節點部署不保證授權流程連續

## 測試策略

本輪至少要有：

- `go test ./...`
- `python -m tests.python`

重點驗證：

- `/x/auth` 分流
- `/x/login` 帳密與 trusted device 分流
- `/x/verify` 建立 trusted device
- `/x/token` 正常與錯誤回應
- `/x/userinfo` claims 與 bearer 驗證

## 完成定義

以下條件全部成立才算本輪完成：

- `au4ul4` 成為正式 session cookie
- trusted device 能被建立與重用
- `/x/auth` 能依 session/device 正確分流
- `/x/login` 能正確進入 verify 流程
- `/x/verify` 成功後能把裝置設為 trusted 並完成授權
- token header 含 `kid`
- discovery 與實作一致
- `/x/userinfo` 回傳至少 `sub/email/name`
- `go test ./...` 通過
