## Why
- 使用者忘記密碼時缺乏自助重設，支援負擔集中在管理員並阻塞 OIDC 授權流程。
- 現行僅有登入端點，無法處理帳號接管或疑似洩漏時的強制重置，安全風險未被涵蓋。
- Email/SMTP 已接好，缺少規範化的重設流程與 token 風險控管。

## What Changes
- 新增 POST `/x/forgot-password`：接受 username 或 email，生成一次性、簽名且具 TTL 的 reset token（含 Request-Id），存放雜湊並透過 Outlook/SMTP 寄送重設連結或 token。
- 新增 POST `/x/reset-password`：驗證 reset token + 新密碼（強度與重複檢查），成功後更新密碼雜湊、作廢既有登入 cookie/授權 cache，並記錄安全事件。
- 擴充 OpenSpec `auth/password-reset` 能力，補充正/反向情境與錯誤碼；新增單元/整合測試涵蓋 happy path、過期 token、暴力攻擊節流。

## Impact
- Affected specs: `auth/password-reset`
- Affected code: `router/auth.go`, `controller/password.go`（或 `controller/user.go`）、`service/email`、`common/crypto.go`、`model/user.go`、安全日誌/中介層設定
