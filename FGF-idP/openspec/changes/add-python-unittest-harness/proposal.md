## Why
- 目前沒有自動化 HTTP 端點測試；OIDC/OAuth2 流程依賴 cookies 與重導，手動驗證易漏。
- 需要可重用的 Python unittest 測試模組，支援 cookies/session 持續、基底 URL/憑證配置，才能對 `/x/*`、`.well-known` 等端點做回歸。

## What Changes
- 新增 Python unittest 測試框架與模組化元件：基底 client、cookie-aware session、helpers 產生請求/驗證 JSON 或重導。
- 為主要端點建立測試案例骨架（`/.well-known/openid-configuration`、`/.well-known/keys`、`/x/auth` happy/error、`/x/token` 基本交換、`/x/userinfo` 權杖驗證），可逐步擴充。
- 提供環境變數或設定檔讓測試切換 base URL、client 資訊、使用者帳密；產出執行說明與 CI 入口。

## Impact
- Affected specs: `testing/http`
- Affected code: 新增 `tests/python/` (unittest modules, helper), 可能需 `.env.example`/README 說明；CI 任務或腳本新增以執行 Python 測試。
