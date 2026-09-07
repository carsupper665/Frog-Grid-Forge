# Project Context

## Purpose
Frog Grid Forge Identity Provider（FGF-idP）提供組織內部與合作服務使用的 OAuth2 Authorization Code（含 PKCE）與 OpenID Connect 身分核發能力。啟動時會載入環境變數、初始化資料庫、布建 `.well-known` 端點與 `/x` 授權流程，並將關鍵事件寫入系統日誌與 Discord 通報。

## Tech Stack
- Go 1.24.4 與 Go modules
- Gin + gin-contrib（gzip、CORS、logger、限流）
- GORM + PostgreSQL（正式）/SQLite（本機）資料層
- golang-jwt/jwt、godotenv、bytedance gopkg、x/crypto 等安全與工具套件
- 自建 RSA 金鑰 + JWT-cookie (`au4ul4`) 驅動登入狀態
- SMTP/Outlook、Discord Webhook 整合
- 預設執行埠 3000（`PORT` 可覆寫）；`DEBUG=true` 保留 Gin Debug mode，否則強制 Release mode 並啟用 gzip/CORS/限流中介層。

## Project Conventions

### Code Style
- 採 gofmt 預設與 idiomatic Go；HTTP handler 以 `*gin.Context` 為中心處理 JSON 輸出/錯誤。
- 環境變數與設定透過 `common.LoadEnv`、`common.GetEnvOrDefault*` 取得，不直接 `os.Getenv`。
- 日誌統一使用 `common.SysLog/SysError/FatalLog`，需附 Request-Id（`FGF-Request-Id`）。
- color constants 僅用於日誌；controller/服務層避免直接 fmt.Print。
- Gin `NoRoute` 會 301 重導到 `FRONTEND_BASE_URL` + 原始路徑，由前端處理 SPA 路由。

### Architecture Patterns
- `main -> router -> controller -> service/model` 分層；`main` 載入 env、初始化 DB 與 router，`router` 註冊 gzip/CORS/限流，中介層含 Request-Id、panic recovery。
- `common` 提供常數、加解密、email/JWT/環境 helper；`controller` 僅處理 HTTP，資料庫操作集中在 `model`。
- 授權碼流程使用 in-memory `sync.RWMutex` cache 儲存 `AuthRequest`、`AuthCode`；啟動時確認 JWK metadata、金鑰與預設 OAuth client。
- `.well-known` 與 `/x` 群組掛載 gzip/CORS/全域 IP rate-limit；`request-id`/logger middleware 已實作但目前未在 router 掛載，需注意追蹤鏈遺失。
- 授權碼有效期 5 分鐘且僅存於記憶體，服務重啟或節點切換會使快取遺失。

### Testing Strategy
- 目前缺 `_test.go`，開發者以本機請求驗證。新功能應建立單元或整合測試（`go test ./...`）涵蓋密鑰載入、資料庫遷移與 controller happy/failed path。
- 變更前後至少手動驗證 `.well-known/*` 與 `/x` OIDC 流程；安全相關（JWT、密碼哈希）需加入 regression 測試。

### Git Workflow
- `main` 為穩定分支；依每個 OpenSpec `change-id` 建立 feature branch，提交訊息附 change-id 便於追蹤。
- 行為變更、新功能、架構調整須先完成 Stage 1 proposal 並通過審核；小型修補（typo、設定）可直接在 `main`。
- 合併前確認 `openspec validate --strict` 與 `go test ./...` 通過，並在 `tasks.md` 全數勾選完成。

## Domain Context
- 服務暴露 `.well-known/openid-configuration`、`/keys`，以及 `/x` 底下的 `/auth`、`/login`、`/token`、`/userinfo` 流程，僅支援 `response_type=code` 且 `scope` 需含 `openid`。
- 授權碼與 Login Request-Id 綁定，成功登入後才會使用 PKCE code challenge 交換 token。
- DB 內有 `JakMetadata`、`JwkKey`、`Client`、`User` 等 OIDC/用戶資料；啟動時可依 `CREATE_ROOT_USER` 自動建立 Root 帳號。
- 初始化時只有在 `DEBUG=true` 或 `ALLOW_INSECURE_DEFAULT_CLIENT=true` 時才會建立預設 OAuth client `fgf-mc-panel`（空白 secret）與本機 callback URI 陣列；meta 來源為 `BACKEND_BASE_URL` + `PORT`。
- JWK metadata 預設組合 `http://localhost:/well-known/keys`（會漏 port/斜線），實際 JWKS 綁在 `/.well-known/keys`。

## Important Constraints
- `.env` 必須提供 `SQL_DSN`（未設則改用 SQLite）、SMTP、Discord webhook、root credentials 等敏感資訊。
- RSA 金鑰需存在或由 `common.GenerateRSAKeyPair` 於 `PRIV_KEY_PATH/PUB_KEY_PATH` 自動產生，否則 JWT 簽章與 JWKS 會失效。
- 伺服器預設 Release mode，需依 `common.GlobalApiRateLimit*` 施加限流；Request-Id 與 panic recovery 必須保持啟用以利追蹤。
- 授權碼 cache 屬揮發性，遺失後必須重新走 `/x/auth`。
- `SESSION_SECRET` 不可使用預設 `random_string`，未設定時會中止啟動；`CRYPTO_SECRET`/`HMAC_SECRET` 若未提供將以 `SESSION_SECRET` 回退。
- DB 連線池預設 `MaxIdle/MaxOpen=150`、`Lifetime=60 分鐘`，可透過 `DB_MAX_*` 與 `DB_CONN_LIFETIME` 微調；`SQL_LOG_DSN` 可指定獨立日誌資料庫。

## External Dependencies
- PostgreSQL（正式）與 SQLite（開發）資料庫
- Discord Webhook 接收系統錯誤/警示
- SMTP/Outlook（登入通知、未來 2FA 擴充）
- 外部 OAuth 客戶端（e.g., `fgf-mc-panel` 控制台）透過 `/x` callback 進行登入
- Gin、GORM、godotenv、golang-jwt、gin-contrib gzip/CORS、限流 middleware 等 Go 套件

## Current Gaps / OIDC Risks
- `/revoke` 尚未實作；本輪明確不支援 refresh token，Discovery 也不宣告 `refresh_token` 或 `offline_access`。
- Auth request、verification request 與 authorization code cache 仍是 in-memory，服務重啟或多節點部署會使 pending flow 失效。
- Production client provisioning 需手動建立安全 secret；空 secret 的 default client 只允許在 `DEBUG=true` 或 `ALLOW_INSECURE_DEFAULT_CLIENT=true` 時自動建立。
