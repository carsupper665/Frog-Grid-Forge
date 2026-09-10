## 1. Implementation
- [x] 1.1 定義 `/x/login` Request/Response schema（username/email 擇一 + password + req_id），增加輸入驗證與錯誤訊息格式。
- [x] 1.2 依 username/email 查詢使用者，使用 salt + `common.Password2Hash` 驗證密碼並處理不存在或停用帳號的情形。
- [x] 1.3 成功登入時簽發 `au4ul4` JWT HttpOnly/Secure Cookie，payload 需包含 `user_id`、`username`、`typ=session`、`iat`、`exp`。
- [x] 1.4 根據 `req_id` 從 cache 取回 `AuthRequest`，依 trusted device 狀態直接產出授權碼或進入 verify 流程。
- [x] 1.5 增加錯誤處理：credential 錯誤回 401、payload/req_id 錯誤回 400，內部錯誤回 500 並透過 logger 記錄。
- [x] 1.6 補齊單元或整合測試，至少涵蓋成功登入、錯誤密碼、遺失 req_id、untrusted device、verify 與 auth 分流。

## 2. Validation
- [x] 2.1 `go test ./...`
- [x] 2.2 `openspec validate add-password-login-flow --strict`
