package controller

import (
	"FGF-idP/common"
	"FGF-idP/middleware"
	"FGF-idP/model"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

var loginUrl = "/x/login?req_id="

type loginReq struct {
	Email    string `json:"email" binding:"omitempty,email"`
	Username string `json:"username" binding:"omitempty"`
	Password string `json:"password" binding:"required"`
	ReqID    string `json:"req_id"   binding:"required"`
}

type tokenReq struct {
	GrantType    string `form:"grant_type"    binding:"required"`
	Code         string `form:"code"          binding:"required"`
	RedirectURI  string `form:"redirect_uri"  binding:"required"`
	ClientID     string `form:"client_id"     binding:"required"`
	ClientSecret string `form:"client_secret"`
	CodeVerifier string `form:"code_verifier"`
}

type AuthRequest struct {
	ID                  string
	ClientID            string // OAuth Client(service id) ID
	RedirectURI         string
	Scope               string
	State               string // Random string from web client
	Nonce               string // To prevent replay attack, put in id_token
	CodeChallenge       string
	CodeChallengeMethod string
	UserID              *uint   // 還沒登入時為 nil
	EmailVerifyToken    *string // Email verification token for new device login
}

type AuthCode struct {
	Code                string
	ClientID            string
	UserID              uint
	RedirectURI         string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	IsUsed              bool
}

// In-memory cache for auth requests and auth codes

type CodeCache struct {
	AuthCodes map[string]*AuthCode
	MU        sync.RWMutex
}
type ReqCache struct {
	AuthReqs map[string]*AuthRequest
	MU       sync.RWMutex
}

var (
	AuthCodesCache *CodeCache
	AuthReqsCache  *ReqCache
)

func InitAuthCache() {
	AuthCodesCache = &CodeCache{
		AuthCodes: make(map[string]*AuthCode),
	}
	AuthReqsCache = &ReqCache{
		AuthReqs: make(map[string]*AuthRequest),
	}
}

func Logout(c *gin.Context) {
	token := c.GetHeader("Authorization")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_token"})
		return
	}
	if strings.HasPrefix(token, "Bearer ") {
		token = strings.TrimPrefix(token, "Bearer ")
	}
	payload, err := common.GetJWTPayload(token)

	if err != nil {
		if err.(*jwt.ValidationError).Errors&jwt.ValidationErrorExpired != 0 {
			c.JSON(http.StatusOK, gin.H{"message": "Already logged out"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_token"})
		return
	}
	expRaw, ok := payload["exp"]
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_exp"})
		return
	}
	// 可能有問題
	expFloat, ok := expRaw.(float64)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_exp_type"})
		return
	}

	exp := int64(expFloat) // seconds since epoch

	middleware.TokenStore.Mark(token, time.Duration(exp))
	c.JSON(http.StatusOK, gin.H{"message": "logged_out"})

	return
}

// Login [user input] -> [Auth Req check] -> [Validate creds] -> [Issue Auth Code + Redirect]
func Login(c *gin.Context) {
	var req loginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	//c.GetHeader("")

	if req.ReqID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_req_id"})
		return
	}

	authReq, exist := getAuthRequest(req.ReqID)
	if !exist {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_req_id"})
		return
	}

	var user model.User
	var loginErr error
	if req.Email != "" {
		user, loginErr = model.LoginByEmail(req.Email)
		if loginErr != nil {
			common.LogError(c, "LoginByEmail error: "+loginErr.Error())
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials"})
			return
		}
	} else if req.Username != "" {
		user, loginErr = model.LoginByName(req.Username)
		if loginErr != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials"})
			return
		}
	}
	password := req.Password + user.Salt
	valid := common.ValidatePasswordAndHash(password, user.Password)
	if !valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "wrong_password"})
		return
	}

	// Check Device id is in User login Allowed Devices
	dId, dIdErr := c.Cookie(common.DeviceCookieName)
	if dIdErr != nil {
		if errors.Is(dIdErr, http.ErrNoCookie) {
			userStr := strconv.FormatUint(uint64(user.ID), 10)
			dId = common.GetRandomString(16) + userStr
			c.SetCookie(common.DeviceCookieName, dId, 360*24*60*60, "/", "", false, true)
			CreateVerificationToken(c, user, authReq.ID)
			c.JSON(203, gin.H{"message": "new_device_detected, Varify code sent to email", "email": user.Email})
			return
		}
		common.LogError(c.Request.Context(), "Device cookie error: "+dIdErr.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "cookie_error"})
		return

	}

	isExist, err := model.IsDeviceExists(dId)
	if err != nil || !isExist {
		if err != nil { // Just in case err is not nil
			common.LogError(c.Request.Context(), fmt.Sprintf("Device existence check error: %v", err))
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized_device"})
		return
	}
	issueCodeAndRedirect(c, authReq, user.ID)

}

func CreateVerificationToken(c *gin.Context, user model.User, reqId string) {
	common.LogDebug(c.Request.Context(), "CreateVerificationCode called for user: "+user.Username)
	emailToken, err := common.GenEmailSignedToken(user.Email)
	if err != nil {
		common.LogError(c.Request.Context(), "GenEmailSignedToken error: "+err.Error())
		return
	}
	err = model.SetVerificationCode(user.ID, emailToken)
	if err != nil {
		if errors.Is(err, model.ErrCodeAlreadySet) {
			return
		}
		common.LogError(c.Request.Context(), "SetVerificationCode error: "+err.Error())
		return
	}

	verifyUrl := common.GetEnvOrDefaultString("FRONTEND_BASE_URL", "http://localhost:3000/") + "/x/verify?t=" + url.QueryEscape(emailToken)

	htmlMsg := fmt.Sprintf(
		`<!DOCTYPE html>
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
	</html>`,
		user.DisplayName,
		verifyUrl,
		common.SystemName,
	)

	email := user.Email

	if email == "" || email == "null" {
		common.LogError(c.Request.Context(), "User email is empty for user: "+user.Username)
	}

	common.LogDebug(c.Request.Context(), "Sending verification code to user: "+user.Username+" Email: "+email)

	err = common.SendEmail(
		"Login Verification Link",
		user.Email, // 使用者的 email
		htmlMsg,
	)

	if err != nil {
		common.LogError(c.Request.Context(), "SendEmail error: "+err.Error()+" SMTP account: "+common.SMTPAccount)
		common.LogError(c.Request.Context(), "Failed to send verification code to user: "+user.Username)
		_ = model.ClearVerificationCode(user.Email) // sent failed, clear the code
		return
	}

	err = setAuthEmailToken(reqId, emailToken)
	if err != nil {
		common.LogError(c.Request.Context(), "setAuthEmailToken error: "+err.Error())
		_ = model.ClearVerificationCode(user.Email) // sent failed, clear the code
		return
	}
}

func EmailVerify(c *gin.Context) {
	token := c.Query("t")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_token"})
		return
	}

	deviceId, err := c.Cookie(common.DeviceCookieName)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_device_cookie"})
		return
	}

	payload, err := common.VerifySignedToken(token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid"})
		return
	}
	user, err := model.GetUserByEmail(payload.UserEmail)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid"})
		return
	}
	authReq, exist := getAuthReqByToken(token)

	if !exist {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_req_id"})
		return
	}
	err = model.ClearVerificationCode(user.Email)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_code"})
			return
		}
		common.LogError(c.Request.Context(), "ClearVerificationCode error: "+err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DB error clearing verification code"})
		return
	}

	ua := c.GetHeader("User-Agent")
	ip := c.ClientIP()
	err = model.SaveDevice(deviceId, ua, ip, user.ID)
	if err != nil {
		common.LogError(c.Request.Context(), "SaveDevice error: "+err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DB error saving device"})
		return
	}

	issueCodeAndRedirect(c, authReq, user.ID)
}

func VerifyAuthCode(c *gin.Context) {

}
func Auth(c *gin.Context) {
	responseType := c.Query("response_type")
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	scope := c.Query("scope")
	state := c.Query("state")
	nonce := c.Query("nonce")
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method")

	// URI Not validated here, will return error to client if invalid
	if isValid, msg, err := model.ValiClientWithUrl(clientID, redirectURI); !isValid || err != nil {
		common.LogError(c.Request.Context(), "Auth client validation error message: "+msg)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error", "req_id": c.Request.Context().Value(common.RequestIdKey)})
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		}
		return
	}

	if responseType != "code" {
		redirectWithAuthError(c, redirectURI, "unsupported_response_type", state)
		return
	}
	if !strings.Contains(scope, "openid") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_scope"})
		return
	}

	reqId := c.Request.Context().Value(common.RequestIdKey)
	authReq := &AuthRequest{
		ID:                  reqId.(string),
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		State:               state,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	}

	payload, _, idUint, err := getPayloadAndId(c)
	if payload == nil || err != nil {
		// JWT 無效，導向登入頁面
		uri := loginUrl + url.QueryEscape(authReq.ID)
		setAuthRequest(authReq) // save to cache
		c.Redirect(http.StatusFound, uri)
		return
	}

	// Redirect back to client with authorization code
	issueCodeAndRedirect(c, authReq, idUint)
}

func redirectWithAuthError(c *gin.Context, redirectURI, errorCode, state string) {
	parsed, err := url.Parse(redirectURI)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	query := parsed.Query()
	query.Set("error", errorCode)
	if state != "" {
		query.Set("state", state)
	}
	parsed.RawQuery = query.Encode()
	c.Redirect(http.StatusFound, parsed.String())
}

func Token(c *gin.Context) {
	var req tokenReq
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	if req.GrantType != "authorization_code" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
		return
	}

	isValid, msg, err := model.ValiClient(req.ClientID, req.RedirectURI, req.ClientSecret)
	if err != nil {
		common.LogError(c.Request.Context(), "Token validation error: "+msg)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}
	if !isValid {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}

	authCode, err := verifyAuthCodeInternal(req.Code, req.ClientID, req.RedirectURI, req.CodeVerifier)
	if err != nil {
		common.LogError(c.Request.Context(), "Token verifyAuthCodeInternal error: "+err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}

	// Issue tokens (access token, id token, refresh token)
	accessToken, idToken, _, err := issueTokens(authCode.UserID, authCode.ClientID, authCode.Scope, authCode.Nonce)
	if err != nil {
		common.LogError(c.Request.Context(), "Token issueTokens error: "+err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	// TODO refresh token
	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"id_token":      idToken,
		"refresh_token": nil,
		"token_type":    "Bearer",
		"expires_in":    common.JwtExpireSeconds,
	})

}

func UserInfo(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	parts := strings.Fields(authHeader)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		unauthorizedUserInfo(c)
		return
	}

	payload, err := common.GetJWTPayload(parts[1])
	if err != nil {
		unauthorizedUserInfo(c)
		return
	}

	sub, ok := payload["sub"].(string)
	if !ok || sub == "" {
		unauthorizedUserInfo(c)
		return
	}

	c.JSON(http.StatusOK, gin.H{"sub": sub})
}

func unauthorizedUserInfo(c *gin.Context) {
	c.Header("WWW-Authenticate", `Bearer realm="FGF-idP"`)
	c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
}

func verifyAuthCodeInternal(code, clientID, redirectURI, codeVerifier string) (*AuthCode, error) {
	AuthCodesCache.MU.Lock()
	defer AuthCodesCache.MU.Unlock()
	authCode, exist := AuthCodesCache.AuthCodes[code]
	if !exist {
		return nil, fmt.Errorf("auth code not found")
	}
	if authCode.ClientID != clientID {
		return nil, fmt.Errorf("client ID mismatch")
	}
	if authCode.RedirectURI != redirectURI {
		return nil, fmt.Errorf("redirect URI mismatch")
	}
	if time.Now().After(authCode.ExpiresAt) {
		return nil, fmt.Errorf("auth code expired")
	}
	if authCode.IsUsed {
		return nil, fmt.Errorf("auth code already used")
	}
	// Verify PKCE code challenge
	if authCode.CodeChallenge != "" {
		if !common.VerifyPKCE(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			return nil, fmt.Errorf("invalid code verifier")
		}
	}
	// Mark code as used
	authCode.IsUsed = true
	AuthCodesCache.AuthCodes[code] = authCode
	return authCode, nil
}

func issueTokens(userID uint, clientID, scope, nonce string) (accessToken string, idToken string, refreshToken string, err error) {
	accessToken, err = common.GenerateAccessToken(userID, clientID, scope)
	if err != nil {
		return "", "", "", err
	}
	idToken, err = common.GenerateIDToken(userID, clientID, nonce)

	if err != nil {
		return "", "", "", err
	}
	// TODO: 之後實作 refresh token
	refreshToken = ""

	return accessToken, idToken, refreshToken, nil
}

func issueCodeAndRedirect(c *gin.Context, authReq *AuthRequest, userId uint) {
	code := common.GetRandomString(32)
	authCode := &AuthCode{
		ClientID:            authReq.ClientID,
		UserID:              userId,
		RedirectURI:         authReq.RedirectURI,
		Scope:               authReq.Scope,
		Nonce:               authReq.Nonce,
		CodeChallenge:       authReq.CodeChallenge,
		CodeChallengeMethod: authReq.CodeChallengeMethod,
		Code:                code,
		ExpiresAt:           time.Now().Add(5 * time.Minute),
		IsUsed:              false,
	}
	setAuthCode(authCode)
	deleteAuthRequest(authReq.ID)
	// Redirect back to client with authorization code
	uri := authReq.RedirectURI + "?code=" + url.QueryEscape(code)
	if authReq.State != "" {
		uri += "&state=" + url.QueryEscape(authReq.State)
	}
	c.Redirect(http.StatusFound, uri)
}

func setAuthRequest(req *AuthRequest) {
	AuthReqsCache.MU.Lock()
	defer AuthReqsCache.MU.Unlock()
	AuthReqsCache.AuthReqs[req.ID] = req
}

func deleteAuthRequest(id string) {
	AuthReqsCache.MU.Lock()
	defer AuthReqsCache.MU.Unlock()
	delete(AuthReqsCache.AuthReqs, id)
}

func setAuthCode(code *AuthCode) {
	AuthCodesCache.MU.Lock()
	defer AuthCodesCache.MU.Unlock()
	AuthCodesCache.AuthCodes[code.Code] = code
}

func getAuthRequest(id string) (*AuthRequest, bool) {
	AuthReqsCache.MU.RLock()
	defer AuthReqsCache.MU.RUnlock()
	req, exist := AuthReqsCache.AuthReqs[id]
	return req, exist
}

func setAuthEmailToken(id string, emailToken string) (err error) {
	AuthReqsCache.MU.Lock()
	defer AuthReqsCache.MU.Unlock()
	req, exist := AuthReqsCache.AuthReqs[id]
	if !exist {
		return fmt.Errorf("auth request not found")
	}
	req.EmailVerifyToken = &emailToken
	AuthReqsCache.AuthReqs[id] = req
	return nil
}

func getAuthReqByToken(emailToken string) (*AuthRequest, bool) {
	// TODO: for loop search Takes too many time, need to optimize later
	AuthReqsCache.MU.RLock()

	authReqs := AuthReqsCache.AuthReqs
	AuthReqsCache.MU.RUnlock()

	for _, req := range authReqs {
		if req.EmailVerifyToken != nil && *req.EmailVerifyToken == emailToken {
			return req, true
		}
	}
	return nil, false
}

func getAuthCode(codeStr string) (*AuthCode, bool) {
	AuthCodesCache.MU.RLock()
	defer AuthCodesCache.MU.RUnlock()
	code, exist := AuthCodesCache.AuthCodes[codeStr]
	return code, exist
}

func getPayloadAndId(c *gin.Context) (map[string]interface{}, string, uint, error) {
	token, err := c.Cookie(common.JwtCookieName)
	if err != nil {
		return nil, "", 0, fmt.Errorf("failed to get JWT cookie: %w", err)
	}
	payload, err := common.GetJWTPayload(token)
	if err != nil {
		common.LogDebug(c.Request.Context(), "JWT error: "+err.Error())
		return nil, "", 0, fmt.Errorf("invalid token: %w", err)
	}

	rawUID, _ := payload["user_id"]
	uid, parseErr := strconv.ParseUint(rawUID.(string), 10, 32)

	if parseErr != nil {
		common.LogDebug(c.Request.Context(), "Parsing user id error: "+parseErr.Error())
		return nil, "", 0, fmt.Errorf("failed to parse user ID: %w", parseErr)
	}
	return payload, rawUID.(string), uint(uid), nil
}

func LoginHTML(c *gin.Context) {
	// return a index.html
}
