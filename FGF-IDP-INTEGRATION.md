# FGF IDP 三服務登入

`mc-server-backend`、`trading`、`chaintrace` 都提供「使用 FGF 登入」logo。流程為服務登入入口 → FGF IDP 的 `/login` → 帳密與首次裝置信任驗證 → 回到原服務。已有有效 IDP session 與可信裝置時，後續服務可直接完成單一登入。

## 本機啟動與驗收

在 Frog-Grid-Forge 根目錄執行。需要 Go、Node.js 及 Chrome；Go 與前端依賴依各模組鎖定檔安裝。

```powershell
npm --prefix web ci
npm --prefix mc-server-backend/web ci
npm --prefix trading/web ci
npm --prefix chaintrace/frontend ci
npm --prefix trading/web run build
node scripts/fgf-local.cjs
```

啟動器編譯 IDP 與三個 Go 服務，用 IDP 的正式管理 API 註冊三個不同 client，然後啟動 MC／ChainTrace 開發前端及 Trading 內嵌前端。所有後端從全新的 `output/fgf-local/run-<timestamp>/` 工作目錄啟動，使用獨立資料庫及隨機 secret，不載入原有後端 `.env`；Trading 固定 paper 模式並開啟 kill switch。MC 啟動所需的靜態版本資料由啟動器複製進隔離目錄。

| 服務 | 本機入口 | 已註冊 callback |
| --- | --- | --- |
| MC | http://127.0.0.1:15173/login | http://127.0.0.1:15173/login/fgf/callback |
| Trading | http://127.0.0.1:18081/login | http://127.0.0.1:18081/api/auth/fgf/callback |
| ChainTrace | http://127.0.0.1:15175/login | http://127.0.0.1:15175/login/fgf/callback |

IDP 為 `http://127.0.0.1:15525`。本機帳號名稱是 `fgf-local`；每次啟動產生的密碼存於被 Git 忽略的 `output/fgf-local/current.json`。請勿提交或分享該檔案。

點選任一服務的 FGF logo，使用該帳號登入。第一次裝置驗證的郵件會由真實 SMTP 送到本機測試信箱 `http://127.0.0.1:15526`；重新整理信箱，在同一瀏覽器開啟驗證連結，即會返回原服務。這是本機 SMTP 投遞驗收，不代表已驗證外部正式信箱的投遞。

三個服務一起啟動會使用 15525、15526、15527、18080、18081、18082、15173、15175 埠。啟動器遇到已占用的埠會停止，不會重用或停止既有服務。結束時在啟動器終端按 Ctrl+C；再次啟動會使用全新的隔離資料。

在已啟動的環境執行瀏覽器驗收：

```powershell
node web/tests/services.e2e.cjs
```

也可以在上述埠尚未占用時一次啟動、驗收並關閉：

```powershell
node scripts/fgf-local.cjs --test
```

`--skip-build` 僅供 Go 原始碼未變更且已有編譯結果時加快啟動。改動 Trading 前端後需先重跑 `npm --prefix trading/web run build`，因為它嵌入 Go 執行檔。

瀏覽器測試使用真實 IDP、三個服務與本機 SMTP，包含錯誤密碼重試、新裝置驗證、callback、登入後 API、重新整理、Trading／ChainTrace 登出、跨服務 SSO 及匿名拒絕。截圖及結果存於 `output/playwright/fgf-services/`。

## 個別服務設定

先在 IDP `/admin` 建立 client，scope 使用 `openid profile email`，redirect URI 必須精確匹配上表或實際部署網址。client secret 只在後端設定，從 IDP 建立回應取得，不放入前端變數。

```dotenv
FGF_IDP_ISSUER=http://127.0.0.1:15525
FGF_IDP_CLIENT_ID=<此服務的 client ID>
FGF_IDP_CLIENT_SECRET=<IDP 核發的 secret，至少 32 字元>
FGF_IDP_REDIRECT_URL=<此服務的精確 callback>
```

Trading 另外要求 `FGF_IDP_ALLOWED_SUBJECTS`，填入可使用此交易工作區的 IDP `sub`，多個以逗號分隔。FGF 的 `sub` 是 IDP 使用者 ID；本機啟動器會從管理 API 取得正確 ID。Trading 是單一共用交易工作區，登入白名單不會產生每人獨立的交易帳戶。交易寫入 API 仍需要原本的 `LIVE_TRADING_API_TOKEN`，原有機器 token 也仍可直接呼叫 API；公開 listener 仍只提供既有的 health／Email restart 路由。

MC 開發代理可用 `MC_BACKEND_URL` 指定 Go API；Trading Vite 開發代理可用 `TRADING_BACKEND_URL` 指定 Go API。ChainTrace 前端只設定 `CHAINTRACE_BACKEND_URL`，所有 client secret、授權碼交換與 Owner 建立都在 Go API；BFF 只轉送登入並保存 HttpOnly 憑證。

ChainTrace 的 Cloudflare 本機 Worker 不會預設繼承 shell 的所有環境變數。本機啟動器用篩選過的程序環境並設定 `CLOUDFLARE_INCLUDE_PROCESS_ENV=true`，讓 Worker 讀取隔離 API 位址；自行啟動時也可使用其既有 `frontend/.env`。參考 [Cloudflare 本機環境變數文件](https://developers.cloudflare.com/workers/vite-plugin/reference/cloudflare-environments/)。

## 帳號與安全邊界

授權流程共用 `fgf-oidc` Go 模組，使用 authorization code、S256 PKCE、state、nonce、ID token 的 RSA 簽章／issuer／audience／到期驗證，以及 UserInfo 與 ID token 的 subject 一致性檢查。交易暫存 cookie 具 HttpOnly、SameSite=Lax、加密及十分鐘有效期，並綁定 issuer、client 及用途。正式網址要求 HTTPS，只有 loopback 可使用 HTTP。

各服務 UI 與 IDP 後台的登入者標籤優先顯示 display name，未設定時才使用帳號名稱。MC 的既有登入狀態會在重新整理時從受保護的 `/user/me` 取得顯示資料。IDP 改名後，再次透過 FGF 登入會更新 MC／ChainTrace 的顯示名稱及 Trading session 的名稱，不變更帳號 ID、Email 關聯或權限。

MC 與 ChainTrace 以 issuer 和 subject 的 SHA-256 值保存在 `users.fgf_subject`，新增欄位由既有 GORM migration 處理。每次 FGF 登入都以 IDP 為準同步 role 與顯示名稱：IDP 的 root（6）在 MC／ChainTrace 也是 root，admin（4）在兩個服務中沒有對應的特殊權限，等同一般使用者；在服務端手動調整過的 role 會在下次 FGF 登入時被 IDP 的值覆蓋。服務本機密碼登入仍保留，但 FGF 新建帳號不具有可用的本機密碼。

FGF 登入依序比對：已關聯的 `fgf_subject`、相同 email 的既有本機帳號（此時寫入關聯，帳號名稱、資料與密碼登入保留）、都沒有才建立新帳號。因為 IDP 的 email 只能由 IDP 管理員設定，等於 IDP 管理員能決定任何 email 對應到哪個服務帳號；只有已軟刪除的帳號仍佔用唯一鍵時登入才會被拒，需管理員先處理。

服務登出清除／撤銷的是各服務 session；FGF IDP session 與裝置信任仍保留，因此再次點 FGF logo 可能直接登入。這不是跨所有服務的全域登出。

## 原始碼與測試

三個 submodule 的 `go.mod` 都以本機 `replace` 指向 `../fgf-oidc`。在這個父專案 checkout 中，模組只透過共用 Go API 相依，不互相存取資料庫。單獨複製某個 submodule 時，也需要取得相鄰的 `fgf-oidc` 目錄，或在共用模組正式發布後改用發布版本；目前不宣稱它已可從遠端下載。

本輪登入瀏覽器驗收、共用 OIDC 測試、Trading config/httpapi 測試、ChainTrace Go 全套、三個前端建置、ChainTrace 型別與 14 項登入回歸、Trading 前端 6 項測試通過。MC Go 與前端全套仍缺少既有的 `test/mrcpack/test_mod_pack.mrpack` fixture，前端其餘 31 項通過。Trading 全套曾遇到 Windows 暫存目錄清除與既有非同步會計測試失敗，兩個失敗案例分別重跑後通過。
