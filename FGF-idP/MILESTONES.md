# Milestones

這份清單用來把目前工作拆成可獨立提交的四個主題。

## 1. OIDC 相容性

建議涵蓋：

- `controller/jwk.go`
- `controller/user.go`
- `router/auth.go`
- `openspec/changes/add-oidc-core-compliance/`
- 與 discovery、token、userinfo 相關測試

建議 commit 範圍：

- discovery metadata 與 JWKS 對齊
- `/x/auth` OIDC 錯誤重導
- `/x/token` claims 與錯誤碼
- `/x/userinfo` claims 與 bearer 驗證

## 2. 登入 / 驗證流程

建議涵蓋：

- `controller/user.go`
- `model/user.go`
- `/x/login`、`/x/verify` 相關測試
- `openspec/changes/add-password-login-flow/`
- `openspec/changes/add-password-reset-flow/`

建議 commit 範圍：

- password login 行為修補
- device verification 行為修補
- password reset 規格或實作補齊

## 3. 測試基建

建議涵蓋：

- `controller/*_test.go`
- `tests/python/`
- `tests/web/`
- `web/`

建議 commit 範圍：

- Go handler/regression tests
- Python HTTP suite 與固定入口
- 手動 smoke tool 或前端測試頁整理

## 4. 文件整理

建議涵蓋：

- `README.md`
- `AGENTS.md`
- `openspec/implementation-audit.md`
- repo hygiene 與版本控制整理

建議 commit 範圍：

- 後端啟動與測試說明
- spec/實作落差盤點
- 工作區與版本控制規範
