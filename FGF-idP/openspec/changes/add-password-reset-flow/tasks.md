## 1. Implementation
- [ ] 1.1 定義 reset token payload（user id/email、issued_at、req_id、nonce、ttl）與雜湊儲存策略；新增環境變數 `RESET_TOKEN_TTL`、`RESET_TOKEN_SECRET`、`RESET_MAX_ATTEMPTS`。
- [ ] 1.2 新增 POST `/x/forgot-password` 路由與 handler：查詢使用者、節流（rate limit + captcha placeholder）、產生 token、寄送含 Request-Id 的郵件模板。
- [ ] 1.3 新增 POST `/x/reset-password` handler：驗證 token 簽章與未過期且未重複使用，檢查新密碼強度、更新 DB 雜湊，清除相關 cache/舊 JWT cookie。
- [ ] 1.4 補充錯誤處理：不存在使用者或節流觸發時回 202/429，token 失效回 400/410，內部錯誤回 500 並送 Discord。
- [ ] 1.5 撰寫測試：token 產生與驗證、過期/重複使用阻擋、成功重設後必須重新登入流程；CI 跑 `go test ./...`。

## 2. Validation
- [ ] 2.1 `openspec validate add-password-reset-flow --strict`
- [ ] 2.2 `go test ./...`
