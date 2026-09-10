## 1. Implementation
- [x] 1.1 建立 `tests/python/`，包含共用 `client.py`（requests Session，cookie/scope 支援）、`config.py`（base URL、client 資訊、帳密由環境變數或 `.env` 讀取）。
- [x] 1.2 實作 discovery/JWKS 基礎測試：`GET /.well-known/openid-configuration`、`/.well-known/keys` 皆回 200，且欄位齊全。
- [x] 1.3 實作 `/x/auth` happy/error flow 測試：驗證合法 redirect 302 帶 `req_id` 或 `error/state`，非法 redirect 400 JSON；驗證 cookies 可跨請求保存。
- [x] 1.4 實作 `/x/token` 基礎交換與 `/x/userinfo` bearer 驗證測試：成功回傳 access/id token/scope；缺 token 時 userinfo 回 401；不支援 refresh token。
- [x] 1.5 撰寫 README/說明與執行命令（`python -m tests.python`），並提供固定執行入口。

## 2. Validation
- [x] 2.1 `openspec validate add-python-unittest-harness --strict`
- [x] 2.2 `python -m tests.python`
