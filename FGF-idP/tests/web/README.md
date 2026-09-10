# Minimal Web Smoke Test

這是一個最小化手動測試頁，用來快速驗證 FGF-idP 端點:

- `GET /.well-known/openid-configuration`
- `GET /x/auth` (開新分頁)
- `POST /x/token`
- `GET /x/userinfo`

## 快速使用

1. 開啟 `tests/web/minimal-smoke.html`。
2. 設定 `Backend Base URL`、`client_id`、`redirect_uri`。
3. 按 `GET Discovery` 先確認服務可連線。
4. 按 `Open /x/auth` 完成登入並取得 `code`。
5. 把 `code` 貼回頁面，按 `POST /x/token`。
6. 取得 `access_token` 後按 `GET /x/userinfo`。

## 注意

- `redirect_uri` 必須已在資料庫 `client.redirect_uris` 註冊，否則 `/x/auth` 會拒絕。
- 若 auth callback 沒有回到此頁，手動把 callback URL 內的 `code` 貼回即可。
- 本頁是 smoke test，不取代自動化單元/整合測試。
