## 1. Implementation
- [x] 1.1 修正 discovery 與 JWKS：路由使用 `/.well-known/openid-configuration`、`/.well-known/keys`，metadata URL/issuer 以 `BACKEND_BASE_URL` 計算，JWT 簽章 header 設定活躍 `kid`。
- [x] 1.2 `/x/auth` 對合法 redirect URI 的錯誤（response_type/scope）改為 302 重導並附 `error`、`state`；非法 redirect URI 保持 400 JSON。
- [x] 1.3 `/x/token` 保留 access token `scope`、ID Token claims/`kid`，不宣告也不回傳 refresh token；補齊主要錯誤碼（invalid_client、invalid_grant、invalid_request）。
- [x] 1.4 實作 `/x/userinfo`：驗證 Bearer access token，回傳 `sub/email/name`，無效權杖回 401 並設置 `WWW-Authenticate`。
- [x] 1.5 以單元/整合測試驗證 discovery、auth error redirect、token/userinfo claim、`kid` 存在。

## 2. Validation
- [x] 2.1 `openspec validate add-oidc-core-compliance --strict`
- [x] 2.2 `go test ./...`
