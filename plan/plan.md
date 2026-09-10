# FGF-idP Plan

## Phase 1: Session / Device / Verify

- [x] 確認前端 login route 最終路徑
- [x] 確認 `au4ul4` TTL
- [x] 確認 `did` TTL
- [x] 確認 verify 失敗時是回 JSON 還是導前端錯誤頁

### controller/user.go

- [x] 將 `loginUrl` 改成前端 SPA login route
- [x] 新增統一 login redirect helper
- [x] 新增 session cookie 簽發 helper
- [x] 新增 session cookie 清除 helper
- [x] 補 session payload 驗證 helper
- [x] 重寫 `/x/auth` 分流邏輯
- [x] `session 有效 + trusted device` 直接發 code
- [x] `session 無效` 導前端 login
- [x] `session 有效 + device 不可信` 導前端 login
- [x] `/x/auth` 對 `invalid_scope` 改成 redirect error
- [x] `/x/login` 成功後簽發或刷新 `au4ul4`
- [x] `/x/login` 對新裝置建立 `did`
- [x] `/x/login` 對未信任裝置回 `203`
- [x] 移除 `unauthorized_device` 作為主要流程回應
- [x] `/x/verify` 成功後保存 trusted device
- [x] `/x/verify` 成功後完成 auth redirect
- [x] `/x/verify` 錯誤碼明確化
- [x] `LoginHTML()` 改成前端 redirect 或 minimal fallback

### model/user.go

- [x] 補 user-device 關聯檢查 helper
- [x] 確認 trusted device 是以 user 為範圍判斷
- [x] 保留 `SaveDevice` 作為 verify 成功後註冊 trusted device 的入口
- [x] 確認 verification token 重複發送策略

## Phase 2: OIDC Core

### common/crypto.go

- [x] 新增 session token 生成函式
- [x] session claims 加入 `user_id`
- [x] session claims 加入 `username`
- [x] session claims 加入 `typ=session`
- [x] access token JWT header 加入 `kid`
- [x] id token JWT header 加入 `kid`
- [x] access token 保留 `scope`
- [x] id token 保留 `nonce` if present

### common/constants.go / common/init.go

- [x] 拆分 session TTL 與 access token TTL
- [x] 拆分 device cookie TTL
- [x] 視需要加入 env 設定
- [x] 確認 production 可用 `Secure` cookie 策略

### controller/jwk.go

- [x] 修正 discovery `grant_types_supported`
- [x] 修正 discovery `scopes_supported`
- [x] 確保 discovery 只宣告已實作能力
- [x] 檢查 `issuer`、`jwks_uri`、`userinfo_endpoint` 一致性

### model/jwk.go

- [x] 新增 active signing key helper
- [x] 讓 token 簽發可取用 active `kid`
- [x] 保持 `ValiClientWithUrl()` 與 `ValiClient()` 職責分離

### model/main.go

- [x] 確認 metadata 仍由 `BACKEND_BASE_URL` 正確生成
- [x] 確認 discovery URL 與實際部署 URL 一致
- [x] 確認 reverse proxy 場景不會產生錯誤 issuer

### controller/user.go

- [x] `/x/token` 成功回應補 `scope`
- [x] `/x/token` 移除 `refresh_token: null`
- [x] `/x/userinfo` 回 `sub`
- [x] `/x/userinfo` 回 `email`
- [x] `/x/userinfo` 回 `name`
- [x] `/x/userinfo` 可選回 `preferred_username`
- [x] `WWW-Authenticate` 改成帶 `error="invalid_token"`

## Phase 3: 測試

### controller/user_test.go

- [x] 更新 `/x/auth` login redirect 目標測試
- [x] 新增 `session 有效 + trusted device` 測試
- [x] 新增 `session 有效 + untrusted device` 測試
- [x] 新增 `session 無效 + trusted device` 測試
- [x] 新增 login 成功會簽發 session cookie 測試
- [x] 更新新裝置 login -> `203` 測試
- [x] 新增既有未信任裝置 login -> `203` 測試
- [x] 更新 verify success 後 trusted device 建立測試
- [x] 更新 token success 回應欄位測試
- [x] 新增 userinfo success claims 測試
- [x] 新增 token JWT header `kid` 測試

### tests/python/test_auth_flow.py

- [x] 更新 valid auth redirect 目標
- [x] 新增 `invalid_scope` redirect error 測試
- [x] 保留 invalid redirect 測試
- [x] 保留 unsupported response type 測試

### tests/python/test_login_verify_flow.py

- [x] 保留 `missing req_id`
- [x] 保留 `invalid req_id`
- [x] 新增 `wrong password`
- [x] 新增 `untrusted device -> 203`
- [x] 視可行性新增 verify success smoke

### tests/python/test_token_userinfo.py

- [x] token 成功案例驗 `scope`
- [x] token 成功案例驗不含 `refresh_token`
- [x] userinfo 成功案例驗 `sub`
- [x] userinfo 成功案例驗 `email`
- [x] userinfo 成功案例驗 `name`
- [x] invalid token 驗 `WWW-Authenticate`

### tests/python/client.py

- [x] 視需要補 cookie 操作 helper
- [x] 確認前端 redirect 仍可檢查 `Location`

### 測試命令

- [x] `go test ./...`
- [x] `python -m tests.python`

## Phase 4: 文件

### README.md

- [x] 更新最終登入模型說明
- [x] 補 `au4ul4` 說明
- [x] 補 `did` 說明
- [x] 補 `/x/auth`、`/x/login`、`/x/verify`、`/x/token`、`/x/userinfo`
- [x] 註明不支援 refresh token
- [x] 註明不支援 password reset
- [x] 註明 auth cache 為 in-memory

### tests/python/README.md

- [x] 補 session/device/verify 測試說明
- [x] 補測試前置條件
- [x] 補固定執行命令

### openspec/implementation-audit.md

- [x] 更新 OIDC core gap 狀態
- [x] 更新 password login flow 狀態
- [x] 記錄 refresh token 不做
- [x] 記錄 password reset 不做
- [x] 記錄 in-memory auth cache 保留

### web/README.md 或前端文件

- [x] 說明 login route 會收到 `req_id`
- [x] 說明 login route 可能收到 `reason`
- [x] 說明 `203` 的 UX
- [x] 說明 verify link 完成後會直接回 callback

## 最終驗收

- [x] `au4ul4` 為正式長登入 session
- [x] trusted device 流程可建立並重用
- [x] `/x/auth` 分流符合設計
- [x] `/x/login` 成功後能 direct code 或進入 verify
- [x] `/x/verify` 成功後能建立 trusted device
- [x] token header 含 `kid`
- [x] discovery 與實作一致
- [x] `/x/userinfo` 回傳至少 `sub/email/name`
- [x] `go test ./...` 通過
- [x] Python smoke 可執行
- [x] 文件與實作一致
