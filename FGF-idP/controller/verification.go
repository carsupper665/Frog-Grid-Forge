package controller

import (
	"FGF-idP/common"
	"FGF-idP/model"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// verificationEmailTemplate is table-based with inline styles so mail clients
// render it; the %s slots are filled by buildVerificationEmail in order.
const verificationEmailTemplate = `<!DOCTYPE html>
<html lang="zh-Hant">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width"><title>確認是你在登入</title></head>
<body style="margin:0;padding:0;background:#0b0d12;">
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="background:#0b0d12;padding:32px 12px;">
<tr><td align="center">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%%;background:#10131a;border:1px solid #262a36;border-radius:12px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Noto Sans TC',sans-serif;color:#e6e8ef;">
<tr><td style="padding:36px 40px 0;">
  <table role="presentation" cellpadding="0" cellspacing="0"><tr>
    <td style="width:32px;height:32px;border:1px solid #3a3f4f;border-radius:8px;text-align:center;font-size:12px;font-weight:700;color:#e6e8ef;">GF</td>
    <td style="padding-left:12px;font-size:15px;font-weight:600;color:#e6e8ef;">Grid Forge 身分驗證</td>
  </tr></table>
</td></tr>
<tr><td style="padding:40px 40px 0;">
  <p style="margin:0 0 10px;font-size:12px;font-weight:700;letter-spacing:.08em;color:#8f84d6;">裝置驗證</p>
  <h1 style="margin:0 0 16px;font-size:28px;line-height:1.3;font-weight:700;color:#ffffff;">確認是你在登入</h1>
  <p style="margin:0;font-size:15px;line-height:1.7;color:#b8bcc8;">我們在一台沒見過的裝置上收到你的登入請求。點下面的按鈕完成驗證，這台裝置就會被記住 %s 天。</p>
</td></tr>
<tr><td style="padding:28px 40px 0;">
  <a href="%s" style="display:block;padding:18px 20px;border:1px solid #6f63c4;border-radius:8px;background:#161a26;text-align:center;font-size:16px;font-weight:700;color:#ffffff;text-decoration:none;">驗證這台裝置</a>
  <p style="margin:12px 0 0;font-size:12px;line-height:1.6;color:#7d8290;">連結 %s 分鐘後失效，只能使用一次。按鈕無法點擊時，請把這個網址貼到同一個瀏覽器：<br><span style="word-break:break-all;color:#a4a9b8;">%s</span></p>
</td></tr>
<tr><td style="padding:28px 40px 0;">
  <table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="border-top:1px solid #262a36;border-bottom:1px solid #262a36;font-size:13px;line-height:1.5;">
    <tr><td style="padding:14px 0 4px;width:96px;color:#7d8290;">裝置</td><td style="padding:14px 0 4px;color:#e6e8ef;">%s</td></tr>
    <tr><td style="padding:4px 0;color:#7d8290;">IP 位址</td><td style="padding:4px 0;color:#e6e8ef;">%s</td></tr>
    <tr><td style="padding:4px 0;color:#7d8290;">時間</td><td style="padding:4px 0;color:#e6e8ef;">%s</td></tr>
    <tr><td style="padding:4px 0 14px;color:#7d8290;">應用程式</td><td style="padding:4px 0 14px;color:#e6e8ef;">%s</td></tr>
  </table>
</td></tr>
<tr><td style="padding:22px 40px 0;">
  <p style="margin:0;font-size:13px;line-height:1.7;color:#b8bcc8;">不是你操作的？請忽略這封信，沒有開啟連結就不會有任何登入發生；並儘快通知管理員更換密碼。</p>
</td></tr>
<tr><td style="padding:28px 40px 36px;">
  <p style="margin:0;padding-top:20px;border-top:1px solid #262a36;font-size:12px;line-height:1.7;color:#7d8290;">這封信寄給 %s，因為有人以此帳號登入 Grid Forge。安全通知不可退訂。</p>
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>`

func CreateVerificationToken(c *gin.Context, user model.User, authReq *model.AuthRequest, deviceID string) error {
	common.LogDebug(c.Request.Context(), "CreateVerificationCode called for user: "+user.Username)
	emailToken, err := common.GenEmailSignedToken(user.Email)
	if err != nil {
		common.LogError(c.Request.Context(), "GenEmailSignedToken error: "+err.Error())
		return err
	}
	if err := model.BindAuthVerification(c.Request.Context(), authReq.ID, emailToken, deviceID, user.ID); err != nil {
		common.LogError(c.Request.Context(), "setAuthEmailToken error: "+err.Error())
		return err
	}

	if user.Email == "" || user.Email == "null" {
		common.LogError(c.Request.Context(), "User email is empty for user: "+user.Username)
	}
	if common.SMTPServer == "" && common.SMTPAccount == "" {
		common.LogDebug(c.Request.Context(), "SMTP not configured; verification token stored but email send skipped")
		return nil
	}

	common.LogDebug(c.Request.Context(), "Sending verification code to user: "+user.Username+" Email: "+user.Email)
	if err := common.SendEmail(
		"確認是你在登入 Grid Forge",
		user.Email,
		buildVerificationEmail(user, emailToken, requestingApp(c, authReq), c.GetHeader("User-Agent"), c.ClientIP(), time.Now()),
	); err != nil {
		common.LogError(c.Request.Context(), "SendEmail error: "+err.Error()+" SMTP account: "+common.SMTPAccount)
		common.LogError(c.Request.Context(), "Failed to send verification code to user: "+user.Username)
		return errors.Join(err, model.ConsumeAuthVerification(c.Request.Context(), authReq.ID, emailToken, deviceID))
	}
	return nil
}

// requestingApp names what the user was signing in to. A missing client name
// falls back to the ID rather than hiding the row.
func requestingApp(c *gin.Context, authReq *model.AuthRequest) string {
	if authReq.ClientID == common.AdminConsoleClientID {
		return "管理後台"
	}
	if client, err := model.GetClient(c.Request.Context(), authReq.ClientID); err == nil && client.Name != "" {
		return client.Name
	}
	return authReq.ClientID
}

// describeUserAgent reduces a User-Agent header to "browser · OS" for people;
// the raw header still goes into the trusted device record.
func describeUserAgent(userAgent string) string {
	browser := "未知瀏覽器"
	for _, candidate := range []struct{ marker, name string }{{"Edg/", "Edge"}, {"OPR/", "Opera"}, {"Firefox/", "Firefox"}, {"Chrome/", "Chrome"}, {"Safari/", "Safari"}} {
		if strings.Contains(userAgent, candidate.marker) {
			browser = candidate.name
			break
		}
	}
	system := "未知系統"
	for _, candidate := range []struct{ marker, name string }{{"Windows", "Windows"}, {"Android", "Android"}, {"iPhone", "iOS"}, {"iPad", "iPadOS"}, {"Mac OS X", "macOS"}, {"Linux", "Linux"}} {
		if strings.Contains(userAgent, candidate.marker) {
			system = candidate.name
			break
		}
	}
	return browser + " · " + system
}

func buildVerificationEmail(user model.User, emailToken, app, userAgent, ip string, at time.Time) string {
	backendBase := strings.TrimSuffix(common.GetEnvOrDefaultString("BACKEND_BASE_URL", fmt.Sprintf("http://localhost:%d", common.Port)), "/")
	verifyURL := html.EscapeString(backendBase + "/x/verify?t=" + url.QueryEscape(emailToken))
	return fmt.Sprintf(verificationEmailTemplate,
		strconv.Itoa(common.DeviceCookieExpireSeconds/86400),
		verifyURL,
		strconv.Itoa(int(common.EmailTokenTTL/time.Minute)),
		verifyURL,
		html.EscapeString(describeUserAgent(userAgent)),
		html.EscapeString(ip),
		at.Format("2006-01-02 15:04 -07:00"),
		html.EscapeString(app),
		html.EscapeString(user.Email),
	)
}

func EmailVerify(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Referrer-Policy", "no-referrer")
	token := c.Query("t")
	if token == "" {
		verificationError(c, http.StatusBadRequest, "missing_token")
		return
	}
	deviceID, err := c.Cookie(common.DeviceCookieName)
	if err != nil {
		verificationError(c, http.StatusBadRequest, "missing_device_cookie")
		return
	}

	payload, err := common.VerifySignedToken(token)
	if err != nil {
		if strings.Contains(err.Error(), "expired") {
			verificationError(c, http.StatusBadRequest, "expired_token")
			return
		}
		verificationError(c, http.StatusBadRequest, "invalid_token")
		return
	}
	user, err := model.GetUserByEmail(payload.UserEmail)
	if err != nil {
		verificationError(c, http.StatusBadRequest, "invalid_token")
		return
	}
	authReq, err := model.GetAuthRequestByVerificationToken(c.Request.Context(), token)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		verificationError(c, http.StatusBadRequest, "invalid_req_id")
		return
	}
	if err != nil {
		common.LogError(c.Request.Context(), "Read auth verification: "+err.Error())
		verificationError(c, http.StatusInternalServerError, "server_error")
		return
	}
	if authReq.EmailVerifyUserID == nil || *authReq.EmailVerifyUserID != user.ID {
		verificationError(c, http.StatusBadRequest, "invalid_token")
		return
	}
	if authReq.EmailVerifyDeviceID == nil || *authReq.EmailVerifyDeviceID != deviceID {
		verificationError(c, http.StatusBadRequest, "invalid_device")
		return
	}
	if err := model.ConsumeAuthVerification(c.Request.Context(), authReq.ID, token, deviceID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			verificationError(c, http.StatusBadRequest, "invalid_code")
			return
		}
		common.LogError(c.Request.Context(), "Consume verification error: "+err.Error())
		verificationError(c, http.StatusInternalServerError, "server_error")
		return
	}
	if err := model.SaveDevice(deviceID, c.GetHeader("User-Agent"), c.ClientIP(), user.ID); err != nil {
		common.LogError(c.Request.Context(), "SaveDevice error: "+err.Error())
		verificationError(c, http.StatusInternalServerError, "DB error saving device")
		return
	}
	if err := issueSessionCookie(c, user); err != nil {
		common.LogError(c.Request.Context(), "issue session cookie error: "+err.Error())
		verificationError(c, http.StatusInternalServerError, "server_error")
		return
	}
	if authReq.ClientID == common.AdminConsoleClientID {
		c.Redirect(http.StatusSeeOther, "/admin")
		return
	}
	issueCodeAndRedirect(c, authReq, user.ID)
}

func verificationError(c *gin.Context, status int, code string) {
	if c.NegotiateFormat("application/json", "text/html") != "text/html" {
		c.JSON(status, gin.H{"error": code})
		return
	}
	if status >= http.StatusInternalServerError {
		code = "server_error"
	}
	redirect, err := url.Parse(loginRedirectURL("", ""))
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	query := redirect.Query()
	query.Set("error", code)
	redirect.RawQuery = query.Encode()
	c.Redirect(http.StatusSeeOther, redirect.String())
}
