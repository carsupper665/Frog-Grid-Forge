# OIDC Login Flow Tester

這個資料夾提供一個零建置（no-build）的測試頁，用來驗證 FGF-idP 的登入流程：

- `GET /x/auth`
- `POST /x/login`
- `GET /x/verify`（可選）
- `POST /x/token`

後端預設會把需要登入的 auth request 導到 `FRONTEND_BASE_URL + /login?req_id=...`。這個 tester 已支援 `/login` SPA fallback，會自動讀取 `req_id` 與 `reason`。

## 1) 啟動

在專案根目錄執行：

```powershell
node .\web\server.js
```

預設只綁定在 `http://127.0.0.1:15517`，並代理到 `http://localhost:15515`。

可用環境變數：

```powershell
$env:WEB_PORT="15517"
$env:WEB_HOST="127.0.0.1"
$env:BACKEND_ORIGIN="http://localhost:15515"
node .\web\server.js
```

`x-backend-origin` header 預設只接受 localhost/127.0.0.0/8/::1 目標；若要測試遠端後端，需明確設定 `ALLOW_REMOTE_BACKEND_ORIGIN=true`。

## 2) 測試頁功能

- 流程按鈕：
  - `Step A: Start Auth`：向 `/api/x/auth` 拿 `req_id`
  - `Step B: Login`：送 `/api/x/login`
  - `Step C: Verify`：送 `/api/x/verify?t=...`（首次裝置或 email 驗證）
  - `Step D: Token`：送 `/api/x/token` 兌換 token
- Login route query：
  - `req_id`：後端 auth cache 的 request id，tester 會自動填入 Req ID 欄位。
  - `reason=device_verification_required`：代表 session 有效但 `did` 尚未被此 user 信任，需重新登入並完成 email verify。
- 診斷輸出：
  - 每次 request/response 的 method、headers、body、status 都會記錄
- Cookie 工具（`did`）：
  - `Sync did`：由伺服器端讀取 HttpOnly cookie
  - `Set did`：手動設置 `did`
  - `Clear did`：清除 `did`

## 3) 同源代理介面

本地測試伺服器提供：

- `GET /health`
- `ANY /api/*` -> proxy 到 `BACKEND_ORIGIN`
- `GET /cookie/did`
- `POST /cookie/did/set`
- `POST /cookie/did/clear`

> 註：`/cookie/*` 是測試輔助路由，方便觀察/控制 `did`（尤其後端用 HttpOnly 時）。

## 4) 常見狀況

- `401 invalid_credentials`：帳號或密碼錯誤。
- `203 new_device_detected...`：新裝置，通常要走 email 驗證再做 Step C。
- `203 device_verification_required...`：已有 `did` 但尚未被此 user 信任，UX 應提示使用者完成 email verify。
- `400 invalid_client`：`client_id` / `client_secret` / `redirect_uri` 不匹配。
- `400 invalid_grant`：`code` 無效、過期、已使用或 PKCE 驗證失敗。

## 5) 建議驗證順序

1. Step A 拿到 `req_id`
2. Step B 登入，確認是 `302`（有 `code`）或 `203`（需驗證）
3. 若是 `203`，輸入 verify token 走 Step C；verify 成功會建立 trusted device 並直接回 callback 拿到 `code`
4. Step D 成功拿到 `access_token` / `id_token`
