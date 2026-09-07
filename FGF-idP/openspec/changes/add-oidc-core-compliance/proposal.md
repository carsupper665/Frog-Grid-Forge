## Why
- OIDC 標準行為缺漏：`.well-known/openid-configuration/` 路徑與 metadata URL 組裝與實際 host/port 不一致，JWT header 未帶 `kid`，客戶端無法正確驗證 token。
- `/token` 曾回傳 `refresh_token: null` 且 token/discovery 宣告與實作不一致；`/userinfo`、JWT `kid`、`/auth` redirect error 與 Bearer 錯誤回應也需要對齊本輪 OIDC core 範圍。
- 未修正前會造成 OIDC client 無法完成 discovery、驗證簽章或解析權杖與使用者資訊，影響互通性與安全性。

## What Changes
- 修正 discovery 與 JWKS：統一路徑為 `/.well-known/openid-configuration`、`/.well-known/keys`，metadata 內的 issuer/token/userinfo/logout URL 與實際 host/port 相符，JWT 簽章 header 帶入活躍 `kid`。
- 調整 `/x/auth` 錯誤回傳：對有效 redirect URI 的錯誤以 302 附 `error`、`error_description`、`state` 重導；非法 redirect 則回傳 400。
- `/token` 產出的 access/ID token 使用正確 `aud`/`scope`/`kid`，不回傳 refresh token，並回傳 OIDC 規範的錯誤碼；`/userinfo` 依 Bearer access token 回傳標準 claims。
- 補齊 middleware 掛載與測試，驗證 discovery、auth error redirect、token/userinfo claim 與 `kid` 生成行為。

## Impact
- Affected specs: `oidc/core`
- Affected code: `router/auth.go`, `controller/jwk.go`, `controller/user.go`, `common/crypto.go`（或 token 簽章處理）、middleware 掛載、對應測試
