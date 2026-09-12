# FGF-idP 後端服務

FGF-idP 是一個以 Go 實作的 OIDC/OAuth2 IdP，提供 discovery、JWKS，以及 `/x` 底下的授權、登入、驗證、token 與 userinfo 流程。

## 執行需求

- Go 1.26.0 以上；專案指定的 toolchain 為 Go 1.26.8。
- 使用 PostgreSQL 時，需先建立可連線的資料庫；未設定 `SQL_DSN` 時會使用 SQLite。
- 正式環境若要完成新裝置驗證，需準備可實際寄信的 SMTP 帳號。

## 啟動

在 `FGF-idP/` 目錄執行：

```powershell
go run .
```

如需產生執行檔：

```powershell
go build .
```

程式會先讀取 `FGF-idP/.env`，作業系統中已存在的同名環境變數優先。監聽埠由 `PORT` 決定。

## 環境變數

程式在完全未提供 `.env` 時仍能以開發預設值啟動，因此從「程式能否啟動」來看沒有絕對必填欄位；但那些預設值不適合正式環境。正式部署至少必須明確填寫以下設定：

```env
# 對外公開的 IdP URL，不可含結尾斜線
BACKEND_BASE_URL=https://id.example.com

# 必須是長度足夠、不可預測且跨重啟保持不變的隨機字串
SESSION_SECRET=<產生安全的隨機字串>

# 正式環境必須使用 HTTPS cookie
COOKIE_SECURE=true

# 新裝置 Email 驗證所需
SMTP_SERVER=smtp.example.com
SMTP_PORT=587
SMTP_SSL_ENABLED=false
SMTP_ACCOUNT=idp@example.com
SMTP_FROM=idp@example.com
SMTP_TOKEN=<SMTP 密碼或應用程式密碼>
```

`SESSION_SECRET` 不可使用範例值 `random_string`，否則程式會直接中止。未設定時程式雖會在記憶體中隨機產生，但每次重啟都不同，會使既有 session 與相關簽章失效，因此正式環境必須固定設定。`CRYPTO_SECRET` 與 `HMAC_SECRET` 未設定時會沿用 `SESSION_SECRET`；若要分離金鑰用途，可另外設定兩組不同的安全隨機值。

`SMTP_SERVER`、`SMTP_ACCOUNT` 與 `SMTP_TOKEN` 是正式新裝置驗證流程的必要設定。`SMTP_FROM` 未設定時會沿用 `SMTP_ACCOUNT`，但建議明確填寫。465 埠或 `SMTP_SSL_ENABLED=true` 會使用直接 TLS；常見的 587 埠則保持 `SMTP_SSL_ENABLED=false`。未設定 SMTP 時程式仍會啟動，但只保存驗證 token、不寄信，使用者無法透過正式 UI 完成首次裝置信任。

### 條件式必填

| 使用情境 | 必須設定 | 說明 |
| --- | --- | --- |
| 使用 PostgreSQL | `SQL_DSN` | 只接受 `postgres://` 或 `postgresql://`；其他格式會退回 SQLite。 |
| 啟動時建立 root 帳號 | `CREATE_ROOT_USER=true`、`ROOT_USER_EMAIL`、`ROOT_USER_PASSWORD` | `ROOT_USER_NAME` 可省略，預設為 `root`。密碼雖有開發預設值 `123456`，正式環境不得沿用。 |
| 使用外部登入前端 | `FRONTEND_BASE_URL` | 內建 `/login` 不需設定；外部前端路徑可再用 `FRONTEND_LOGIN_ROUTE` 指定。 |
| 瀏覽器跨來源呼叫 API | `CORS_ALLOWED_ORIGINS` | 以逗號分隔完整且精確的 origin，例如 `https://portal.example.com`；不可使用萬用字元或包含路徑。 |
| 部署在反向代理後方 | `TRUSTED_PROXIES` | 以逗號分隔實際代理 IP 或 CIDR；未設定時不信任任何 forwarded IP header。 |
| 多節點部署 | `SQL_DSN`、固定的 `SESSION_SECRET`、`HMAC_SECRET`、`PRIV_KEY_PATH`、`PUB_KEY_PATH` | 所有節點必須共用 PostgreSQL、issuer、簽章金鑰與 session/HMAC secret。金鑰路徑需指向持久化、共用或一致部署的檔案。 |

### 完整 `.env` 範本

以下範本列出後端目前實際讀取的環境變數。尖括號欄位需要依部署環境替換；空白欄位代表停用該功能或使用內建預設值。

```env
# 服務與公開網址
PORT=15515
DEBUG=false
BACKEND_BASE_URL=https://id.example.com
FRONTEND_BASE_URL=
FRONTEND_LOGIN_ROUTE=/login

# 安全與 token
SESSION_SECRET=<安全隨機字串>
CRYPTO_SECRET=<安全隨機字串；留空則沿用 SESSION_SECRET>
HMAC_SECRET=<安全隨機字串；留空則沿用 SESSION_SECRET>
ACCESS_TOKEN_TTL_SECONDS=604800
SESSION_COOKIE_TTL_SECONDS=2592000
DEVICE_COOKIE_TTL_SECONDS=31104000
COOKIE_SECURE=true
PRIV_KEY_PATH=./keys/priv_key.pem
PUB_KEY_PATH=./keys/pub_key.pem

# 網路邊界
CORS_ALLOWED_ORIGINS=
TRUSTED_PROXIES=
GLOBAL_API_RATE_LIMIT=60
GLOBAL_API_RATE_LIMIT_DURATION=60

# 資料庫；正式多節點部署請填 SQL_DSN
SQL_DSN=postgresql://<user>:<password>@<host>:5432/<database>?sslmode=require
SQLITE_PATH=DB.db?_busy_timeout=5000
SQL_LOG_DSN=
DB_MAX_IDLE_CONNS=150
DB_MAX_OPEN_CONNS=150
DB_CONN_LIFETIME=60

# SMTP；正式新裝置驗證必填
SMTP_SERVER=smtp.example.com
SMTP_PORT=587
SMTP_SSL_ENABLED=false
SMTP_ACCOUNT=idp@example.com
SMTP_FROM=idp@example.com
SMTP_TOKEN=<SMTP 密碼或應用程式密碼>

# 初始 root 帳號；只建議首次初始化時暫時開啟
CREATE_ROOT_USER=false
ROOT_USER_NAME=root
ROOT_USER_EMAIL=<啟用 CREATE_ROOT_USER 時必填>
ROOT_USER_PASSWORD=<啟用 CREATE_ROOT_USER 時必填>

# 開發與相容性選項
ALLOW_INSECURE_DEFAULT_CLIENT=false
MEMORY_CACHE_ENABLED=false
UA_FILTER=false
SYNC_FREQUENCY=60
BATCH_UPDATE_INTERVAL=5
RELAY_TIMEOUT=0
DC_WEBHOOK_URL=
```

`PRIV_KEY_PATH`、`PUB_KEY_PATH` 指定 RSA 金鑰位置；檔案不存在時程式會自動產生。正式環境必須持久化這兩個檔案，否則重建容器或服務後舊 token 將無法驗證。`ALLOW_INSECURE_DEFAULT_CLIENT=true` 或 `DEBUG=true` 時，程式會自動建立空 secret 的本機測試 client `fgf-mc-panel`；正式環境必須保持兩者為 `false`，並自行建立具有安全 secret 的 OAuth client。

`ACCESS_TOKEN_TTL_SECONDS` 預設 7 天，`SESSION_COOKIE_TTL_SECONDS` 預設 30 天，`DEVICE_COOKIE_TTL_SECONDS` 預設 360 天。`COOKIE_SECURE` 未設定時會依 `BACKEND_BASE_URL` 是否以 `https://` 開頭自動決定。`GLOBAL_API_RATE_LIMIT_DURATION` 的單位是秒，`DB_CONN_LIFETIME` 的單位是分鐘。

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

## OIDC 端點

- `GET /x/auth`：支援 authorization code flow；合法 `redirect_uri` 下的 `invalid_scope` / `unsupported_response_type` 會 redirect error。
- `POST /x/login`：接受 JSON `username` 或 `email`、`password`、`req_id`；成功後預設回 `302` 或 `203`；明確指定 `Accept: application/json` 時，以 `200 {"redirect_to":"..."}` 取代成功的 `302`。
- `GET /x/verify`：接受 `t=<verify_token>`，成功後保存 trusted device 並回 callback。
- `POST /x/token`：支援 `grant_type=authorization_code`，回 `access_token`、`id_token`、`token_type`、`expires_in`、`scope`。
- `GET /x/userinfo`：Bearer access token 成功時至少回 `sub`、`email`、`name`，並回 `preferred_username` 與 `role`（使用者的權限等級）。
- `/.well-known/openid-configuration` 只宣告已支援的 `authorization_code` 與 `openid/profile/email`。
- `/.well-known/keys` 回標準 JWKS `{ "keys": [...] }`；access token 與 ID token JWT header 會包含 active `kid`。

## 管理後台

`/admin` 是隨執行檔內嵌的管理主控台，與 `/login` 共用同一份資源目錄與嚴格 CSP。它有**獨立登入口** `POST /x/admin/login`，不需要先註冊 OAuth client，也不必繞授權流程；root 可直接以帳密進入，但**新裝置一樣要做 Email 驗證**：帳密正確而裝置未受信任時回 `203`，驗證連結在同一瀏覽器開啟後會導回 `/admin`；`/x/admin/*` 除了 session 也要求可信裝置 cookie，否則回 `401 device_verification_required`。因此沒有可用的 SMTP 就無法在新裝置進入後台。登出沿用既有的 `POST /x/logout`。

權限採整數等級的 `>=` 門檻比較：

| 等級 | 常數 | 可做的事 |
| --- | --- | --- |
| 0 | `RoleGuestUser` | 無 |
| 1 | `RoleCommonUser` | 一般使用者 |
| 4 | `RoleAdminUser` | 使用者管理 |
| 6 | `RoleRootUser` | 使用者管理 + 服務管理 |

端點：

- `POST /x/admin/login`：JSON `{account, password}`，`account` 可填帳號或 Email。帳號不存在、密碼錯誤、權限不足一律回**完全相同**的 `401 {"error":"invalid_credentials"}`，避免帳號枚舉。裝置未受信任時回 `203 {"message","email"}` 並寄出驗證信。
- `GET /x/admin/me`：回 `{id, username, role}`。
- `GET /x/admin/users?q=&page=&size=`：回 `{users, has_more}`；回應不含 `password`、`salt`、`access_token`。
- `POST /x/admin/users`：建立使用者，接受 `username`、`display_name`（可選）、`email`、`password`、`role`（預設 1）；回 `201` 與不含憑證的使用者資料。
- `GET /x/admin/users/:id`：取得使用者資料；已刪除帳號回 `404`。
- `PATCH /x/admin/users/:id`：編輯 `username`、`display_name`、`email`，未提供的欄位保持原值。權限仍透過下列 `/role` 端點調整。
- `PATCH /x/admin/users/:id/role`：JSON `{"role":4}`，`Content-Type` 必須是 `application/json`。
- `DELETE /x/admin/users/:id`：軟刪除，回 `204`。
- `/x/admin/clients` 及 `/x/admin/clients/:client_id`（含 `/secret` 輪替）：**需要 root（6）**，admin（4）會收到 `403`。

提權守衛由伺服器強制，前端的列停用只是體感：

- `forbidden_self`：不能修改或刪除自己。
- `forbidden_root`：任何人都不能修改或刪除 role 6 的帳號。
- `forbidden_peer`：不能操作權限相同或更高的帳號。
- `forbidden_grant`：不能授予等於或高於自己的等級。

因此 **root 無法透過 API 建立**，只能靠 `CREATE_ROOT_USER` 初始化。

使用者頁右上角提供「新增使用者」，每列有「編輯」與「刪除」。新增表單可設定初始密碼及低於操作者的權限；編輯表單顯示帳號、顯示名稱與 Email。自己的帳號、同級／上級及 Root 帳號無法編輯或刪除，後端會再次檢查。重複帳號／Email 回 `409 user_exists`，包含已軟刪除的帳號；不會覆寫舊資料。

帳號為 3–12 碼英數字、底線、句點或連字號，帳號與 Email 會轉為小寫；顯示名稱最多 20 字。初始密碼至少 12 字元且最多 56 UTF-8 位元組，保留現有 bcrypt 加上 16-byte salt 的格式；表單送出後清空密碼，API 不回傳密碼或 hash。密碼重設維持獨立功能規格。

修改 Email 會清除該使用者的可信裝置、待驗證請求與未兌換授權碼。驗證請求增加 `email_verify_user_id` 綁定，不會因舊 Email 分配給另一帳號就讓舊驗證信登入另一帳號；既有 GORM migration 會新增欄位。升級前尚未完成且沒有此綁定的驗證信需重新從原服務發起登入。


授權一律在每次請求從資料庫重讀 role：session cookie 有效期 30 天且無法針對單一使用者撤銷，快取角色會讓降權延後生效。降權與刪除都在下一次請求立即生效。

服務（OAuth client）管理：

- Client secret 以 bcrypt 儲存，**明文只在建立與輪替的回應中出現一次**，之後無法再取得。
- Redirect URI 必須是絕對的 `http`/`https` 網址，不得含片段（RFC 6749 §3.1.2）或萬用字元，最多 10 條；非 `DEBUG` 模式下強制 `https`，僅 `localhost`、`127.0.0.1`、`[::1]` 例外。
- `grant_types` 與 `response_types` 固定為 `authorization_code` / `code`，不開放設定 —— 伺服器只實作這一種流程。
- 刪除是軟刪除，被刪除的 client 立即無法通過 `/x/auth` 與 `/x/userinfo`。因 `client_id` 是主鍵，已刪除的 ID 無法重用。
- 非 `DEBUG` 且未開啟 `ALLOW_INSECURE_DEFAULT_CLIENT` 時，啟動會掃描並警告仍接受空 secret 的 client（例如預設的 `fgf-mc-panel`），請從後台輪替。

## 已知非目標

- 本輪不支援 refresh token，`/x/token` 不會回 `refresh_token`。
- 本輪不支援 password reset。
- 授權請求、授權碼及撤銷紀錄存於資料庫；跨節點部署需共用資料庫、issuer 與簽章金鑰。

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

## 正式登入頁

`/login` 是隨 Go 執行檔內嵌的正式登入頁，採 2a 森林玻璃設計，不需 Node.js 或前端建置。`/login/assets/` 只提供內嵌資源，不提供目錄瀏覽。未設定 `FRONTEND_BASE_URL` 時，授權流程預設導回同源 `/login`；既有外部 `FRONTEND_BASE_URL` 和 `FRONTEND_LOGIN_ROUTE` 設定仍可覆寫。若之前指向本機 QA 測試台，上線時請移除該設定。

使用者應從原服務發起 `/x/auth`，取得有效登入請求後進入頁面；直接開啟 `/login` 會提示從原服務開始，不會建立假 client。JSON 登入成功的 `redirect_to` 由伺服器核發，前端直接導覽到 callback；token 兌換由原服務負責。新裝置收到 203 後顯示遮罩 Email，使用者須以同一瀏覽器開啟信件連結。驗證會在開啟連結的分頁完成；原分頁不輪詢，也沒有重寄、密碼重設或額外信任天數選項。

正式環境請使用 HTTPS，將 `BACKEND_BASE_URL` 設成對外 IdP 網址，設定 `COOKIE_SECURE=true`、有效 SMTP 與安全的 OAuth client。前端及 `/x/*` 須由同一來源提供，並保持反向代理、資料庫與金鑰設定正確。SMTP 必須實際可投遞郵件，才能完成首次裝置驗證；既有未設定 SMTP 時略過寄送的開發行為不能作為上線驗收依據。其他設定見 `SECURITY-CONFIG.md`。

根目錄的 `web/` 仍是開發測試台，不會被內嵌到正式 Go 執行檔，也不應代理到正式網域；`/cookie/*`、`/test/*` 不屬於正式路由。

## 正式登入頁瀏覽器測試

在 `web/` 執行 `npm ci`，再執行 `node tests/login.e2e.cjs`。測試會啟動 loopback-only、記憶體資料庫的 Go 測試伺服器，結束後關閉；需要 Go 與 Chrome，或先執行 `npx playwright install chromium`。可用 `PLAYWRIGHT_CHROMIUM_EXECUTABLE` 指定測試瀏覽器路徑。15519 埠需可用；`FGF_BROWSER_TEST_ADDR` 由測試腳本自動設定，不需手動填寫。開發測試台的 `WEB_PORT`、`WEB_HOST`、`BACKEND_ORIGIN` 與 `ALLOW_REMOTE_BACKEND_ORIGIN` 請見 [web/README.md](../web/README.md)。

測試包含真實後端的帳密驗證、錯誤重試、裝置驗證回應及 callback 導覽；限流和斷線以瀏覽器攔截模擬。SMTP 投遞與外部服務 callback 內容不在此隔離測試範圍。桌機、手機及信箱等待截圖輸出至 `output/playwright/`。


使用者 CRUD 的實際瀏覽器驗收可在本機 IDP 啟動後，從父專案執行 `node web/tests/admin-users.e2e.cjs`。測試會用目前的本機管理員登入，建立獨立測試使用者、驗證讀取／編輯／持久化／重複資料拒絕，再刪除該測試帳號；也檢查 Root 操作停用及手機版面。截圖位於 `output/playwright/admin-users/`。
