package controller

import (
	"FGF-idP/common"
	"FGF-idP/model"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const verificationEmailTemplate = `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Verification Code</title>
<style>
	body {
	margin: 0;
	padding: 0;
	font-family: sans-serif;
	line-height: 1.4;
	background: linear-gradient(-45deg,
		#ff0000, #ff7f00, #ffff00, #00ff00, #0000ff, #4b0082, #8f00ff);
	background-size: 400%% 400%%;
	animation: rainbow 15s ease infinite;
	}
	@keyframes rainbow {
	0%%   { background-position: 0%% 50%%; }
	50%%  { background-position: 100%% 50%%; }
	100%% { background-position: 0%% 50%%; }
	}
	.container {
	padding: 20px;
	background: rgba(255, 255, 255, 0.8);
	margin: 40px auto;
	max-width: 600px;
	border-radius: 8px;
	}
	p { margin: 1em 0; }
</style>
</head>
<body>
<div class="container">
	<p>Hello %s,</p>
	<p>Your verification Link is: <strong>%s</strong></p>
	<p>
	Please click this Link to verify your login.
	This code will expire in <strong>5 minutes</strong>.
	</p>
	<p>If you did not request this, please ignore this email.</p>
	<br>
	<p>Thank you,<br>The %s Team</p>
</div>
</body>
</html>`

func CreateVerificationToken(c *gin.Context, user model.User, reqID, deviceID string) error {
	common.LogDebug(c.Request.Context(), "CreateVerificationCode called for user: "+user.Username)
	emailToken, err := common.GenEmailSignedToken(user.Email)
	if err != nil {
		common.LogError(c.Request.Context(), "GenEmailSignedToken error: "+err.Error())
		return err
	}
	if err := model.BindAuthVerification(c.Request.Context(), reqID, emailToken, deviceID, user.ID); err != nil {
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
		"Login Verification Link",
		user.Email,
		buildVerificationEmail(user, emailToken),
	); err != nil {
		common.LogError(c.Request.Context(), "SendEmail error: "+err.Error()+" SMTP account: "+common.SMTPAccount)
		common.LogError(c.Request.Context(), "Failed to send verification code to user: "+user.Username)
		return errors.Join(err, model.ConsumeAuthVerification(c.Request.Context(), reqID, emailToken, deviceID))
	}
	return nil
}

func buildVerificationEmail(user model.User, emailToken string) string {
	backendBase := strings.TrimSuffix(common.GetEnvOrDefaultString("BACKEND_BASE_URL", fmt.Sprintf("http://localhost:%d", common.Port)), "/")
	verifyURL := backendBase + "/x/verify?t=" + url.QueryEscape(emailToken)
	return fmt.Sprintf(verificationEmailTemplate, user.DisplayName, verifyURL, common.SystemName)
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
