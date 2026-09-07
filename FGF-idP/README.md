# FGF-idP Backend

FGF-idP 是一個以 Go 實作的 OIDC/OAuth2 IdP，提供 discovery、JWKS，以及 `/x` 底下的授權、登入、驗證、token 與 userinfo 流程。

## 啟動

在 `FGF-idP/` 目錄執行：

```powershell
go run .
```

如需產生執行檔：

```powershell
go build .
```

預設會讀取同目錄 `.env`，並以 `PORT` 決定監聽埠。

## 必要環境變數

最少需要先確認這幾組設定：

```env
BACKEND_BASE_URL=http://localhost:15515
FRONTEND_BASE_URL=http://localhost:15517
FRONTEND_LOGIN_ROUTE=/login
PORT=15515
SESSION_SECRET=<random-string>
CRYPTO_SECRET=<random-string>
HMAC_SECRET=<random-string>
ACCESS_TOKEN_TTL_SECONDS=604800
SESSION_COOKIE_TTL_SECONDS=2592000
DEVICE_COOKIE_TTL_SECONDS=31104000
COOKIE_SECURE=false
ALLOW_INSECURE_DEFAULT_CLIENT=false
```

- `SESSION_SECRET` 不能是預設值 `random_string`，否則程式會直接中止。
- `CRYPTO_SECRET` 與 `HMAC_SECRET` 未提供時會回退到 `SESSION_SECRET`。
- `PRIV_KEY_PATH`、`PUB_KEY_PATH` 可指定 RSA 金鑰路徑；若檔案不存在，啟動時會自動產生。
- `ACCESS_TOKEN_TTL_SECONDS` 控制 access/id token 的 `expires_in` 與 JWT `exp`，預設 7 天。
- `SESSION_COOKIE_TTL_SECONDS` 控制 `au4ul4` 長登入 session cookie，預設 30 天。
- `DEVICE_COOKIE_TTL_SECONDS` 控制 `did` trusted device cookie，預設 360 天。
- `COOKIE_SECURE` 未設定時會依 `BACKEND_BASE_URL` 是否為 `https://` 自動決定。
- `ALLOW_INSECURE_DEFAULT_CLIENT=true` 或 `DEBUG=true` 時，啟動才會自動建立空 secret 的本機測試 client `fgf-mc-panel`；正式環境應手動建立 client 與 secret。

## 資料庫模式

FGF-idP 支援兩種資料庫模式：

- PostgreSQL：設定 `SQL_DSN` 後使用 PostgreSQL。
- SQLite：未設定 `SQL_DSN` 時回退到本機 SQLite，路徑由 `SQLITE_PATH` 控制，預設為 `DB.db?_busy_timeout=5000`。

常用資料庫相關環境變數：

```env
SQL_DSN=
SQLITE_PATH=DB.db?_busy_timeout=5000
DB_MAX_IDLE_CONNS=150
DB_MAX_OPEN_CONNS=150
DB_CONN_LIFETIME=60
```

## 本機帳號與登入驗證

- `CREATE_ROOT_USER=true` 時，啟動會在資料庫內自動建立 root 帳號。
- `ROOT_USER_NAME`、`ROOT_USER_EMAIL`、`ROOT_USER_PASSWORD` 用來決定這個初始帳號。
- `/x/auth` 驗證 client、redirect URI、response type 與 scope 後，會依 `au4ul4` session 與 `did` trusted device 分流。
- `au4ul4` 是正式長登入 session cookie，表示帳密已驗證；它不等同 access token，也不代表裝置已信任。
- `did` 是 HttpOnly device cookie；只有 `/x/verify` 成功後，該 `did` 才會以 user 為範圍存成 trusted device。
- `session 有效 + trusted device` 會直接完成 authorization code redirect。
- `session 無效` 會 302 到 `${FRONTEND_BASE_URL}${FRONTEND_LOGIN_ROUTE}?req_id=...`。
- `session 有效 + device 不可信` 會 302 到 login route，並帶 `reason=device_verification_required`。
- `/x/login` 帳密成功會簽發或刷新 `au4ul4`；trusted device 直接回 callback，untrusted device 回 `203` 並要求 email verify。
- `/x/verify?t=...` 需要 request 內有 `did` cookie，成功後會建立 trusted device 並直接回 callback。
- `SMTP_SERVER`、`SMTP_PORT`、`SMTP_ACCOUNT`、`SMTP_FROM`、`SMTP_TOKEN` 會影響驗證信寄送；若要測首次裝置流程，這組設定要可用。

## OIDC Endpoint

- `GET /x/auth`：支援 authorization code flow；合法 `redirect_uri` 下的 `invalid_scope` / `unsupported_response_type` 會 redirect error。
- `POST /x/login`：接受 JSON `username` 或 `email`、`password`、`req_id`；成功後回 `302` 或 `203`。
- `GET /x/verify`：接受 `t=<verify_token>`，成功後保存 trusted device 並回 callback。
- `POST /x/token`：支援 `grant_type=authorization_code`，回 `access_token`、`id_token`、`token_type`、`expires_in`、`scope`。
- `GET /x/userinfo`：Bearer access token 成功時至少回 `sub`、`email`、`name`，並回 `preferred_username`。
- `/.well-known/openid-configuration` 只宣告已支援的 `authorization_code` 與 `openid/profile/email`。
- `/.well-known/keys` 回標準 JWKS `{ "keys": [...] }`；access token 與 ID token JWT header 會包含 active `kid`。

## 已知非目標

- 本輪不支援 refresh token，`/x/token` 不會回 `refresh_token`。
- 本輪不支援 password reset。
- Auth request 與 authorization code cache 維持 in-memory；服務重啟、跨節點或未共享 session 的部署會讓 pending auth flow 失效。

## 測試方式

Go 測試：

```powershell
go test ./...
```

Python HTTP 測試：

```powershell
python -m pip install -r tests/python/requirements.txt
python -m tests.python
```

- `tests/python/` 主要驗證 discovery、auth、login/verify 錯誤處理、token 與 userinfo。
- Python 測試預設連到 `BACKEND_BASE_URL`；若服務未啟動，會以 `skip` 呈現。
- 更細的手動操作可使用 `python -m tests.python.cli ...` 或 `web/` 測試頁。

## 版本控制建議

應納入版本控制：

- `go.mod`
- `go.sum`
- `tests/`
- `openspec/`
- `AGENTS.md`

應維持忽略：

- `.env`
- `DB.db`
- `main.exe`
- `logs/`
- `*.log`
- `keys/`
- `node_modules/`
