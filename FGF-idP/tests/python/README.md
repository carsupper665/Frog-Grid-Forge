# FGF-idP Python HTTP Tests

## 環境設定
- 預設從 `.env` 或環境變數讀取：  
  - `BACKEND_BASE_URL`（預設 `http://localhost:3000`）  
  - `TEST_CLIENT_ID`（預設 `fgf-mc-panel`）  
  - `TEST_CLIENT_SECRET`（預設空字串）  
  - `TEST_REDIRECT_URI`（預設 `http://localhost:3000/callback`）  
  - `TEST_USERNAME` / `TEST_PASSWORD`（若需登入流程，可自行提供）  
  - `TEST_AUTH_CODE`（可選，用於 `/x/token` 交換；未提供則跳過該測試）  
  - `TEST_ACCESS_TOKEN`（可選，若要加入 userinfo 正向案例）
  - `TEST_VERIFY_TOKEN`（可選，若要加入 verify success smoke）
  - `FGF_TEST_PERSIST_COOKIES=true`（可選，讓 unittest client 使用共享 CLI cookie jar；預設測試只用記憶體 cookies）

## 安裝依賴
```bash
python -m pip install -r tests/python/requirements.txt
```

## 執行方式
```bash
python -m tests.python
```

固定 smoke 指令：

```bash
python -m tests.python
```

若 `BACKEND_BASE_URL` 指向的服務未啟動，HTTP 測試會以 `skip` 呈現；若要跑登入正向/203 分流，需提供 `TEST_USERNAME` 與 `TEST_PASSWORD`，並確認測試 client 與 redirect URI 已在 DB 內註冊。

等價寫法：

```bash
python -m unittest discover -s tests/python
```

### CLI 手動測試
`python -m tests.python.cli <command> [options]`  
指令包含：
- `discovery`：查詢 `/.well-known/openid-configuration`
- `keys`：查詢 `/.well-known/keys`
- `auth`：呼叫 `/x/auth`（支援 `--response-type`、`--scope`、`--state`、`--redirect-uri`、`--code-challenge`）
- `token`：交換 `/x/token`（支援 `--code`、`--client-id`、`--client-secret`、`--prompt-secret`、`--redirect-uri`）
- `userinfo`：查詢 `/x/userinfo`（支援 `--bearer`）；CLI 會維持 cookies（requests.Session + `.cli_cookies.jar`）
- `cookies`：檢視現在的 cookie store 或用 `--clear` 清空 jar；資料寫在 `tests/python/.cli_cookies.jar`，可跨 CLI 重複使用直到刪除

## 測試覆蓋範圍
- Discovery 與 JWKS：`/.well-known/openid-configuration`、`/.well-known/keys` 回 200 並檢查必要欄位。
- Auth 流程：合法 auth request 會 302 到 `/login?req_id=...`；未註冊的 `redirect_uri` 回 400；不支援的 `response_type` 與 `invalid_scope` 在合法 redirect 下 302 並帶 `error`/`state`。
- Login/Verify 錯誤處理：`/x/login` 缺 `req_id` 或使用無效 `req_id` 會回 400；錯誤密碼回 `401 invalid_credentials`；untrusted device 在成功登入後回 `203`；`/x/verify` 缺 token 或無效 token 會回 400。
- Token/UserInfo：`/x/token` 不支援的 `grant_type` 會回 400；成功 response 需含 `scope` 且不含 `refresh_token`；`/x/userinfo` 缺 token 或無效 token 回 401 並帶 `WWW-Authenticate: Bearer error="invalid_token"`；如提供 `TEST_ACCESS_TOKEN`，可驗證 `sub/email/name`。
