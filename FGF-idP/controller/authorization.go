package controller

import (
	"FGF-idP/common"
	"FGF-idP/model"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

const loginReasonDeviceVerificationRequired = "device_verification_required"

func loginRedirectURL(reqID, reason string) string {
	frontendBase := strings.TrimSuffix(common.GetEnvOrDefaultString("FRONTEND_BASE_URL", ""), "/")
	route := common.GetEnvOrDefaultString("FRONTEND_LOGIN_ROUTE", "/login")
	if route == "" {
		route = "/login"
	}
	loginURL := route
	if parsedRoute, err := url.Parse(route); err != nil || !parsedRoute.IsAbs() {
		if !strings.HasPrefix(route, "/") {
			route = "/" + route
		}
		loginURL = frontendBase + route
	}
	parsed, err := url.Parse(loginURL)
	if err != nil {
		parsed, _ = url.Parse(frontendBase + "/login")
	}
	query := parsed.Query()
	if reqID != "" {
		query.Set("req_id", reqID)
	}
	if reason != "" {
		query.Set("reason", reason)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func redirectToLogin(c *gin.Context, authReq *model.AuthRequest, reason string) {
	c.Redirect(http.StatusFound, loginRedirectURL(authReq.ID, reason))
}

func scopeIncludes(scope, required string) bool {
	for _, item := range strings.Fields(scope) {
		if item == required {
			return true
		}
	}
	return false
}

func isValidOIDCScope(scope string) bool {
	fields := strings.Fields(scope)
	if len(fields) == 0 {
		return false
	}
	hasOpenID := false
	for _, item := range fields {
		switch item {
		case "openid":
			hasOpenID = true
		case "profile", "email":
		default:
			return false
		}
	}
	return hasOpenID
}

func scopeIsSubset(scope, registered string) bool {
	allowed := make(map[string]bool)
	for _, item := range strings.Fields(registered) {
		allowed[item] = true
	}
	for _, item := range strings.Fields(scope) {
		if !allowed[item] {
			return false
		}
	}
	return true
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
	client, err := model.GetClient(c.Request.Context(), clientID)
	if err != nil {
		common.LogError(c.Request.Context(), "Auth client scope lookup: "+err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error", "req_id": c.Request.Context().Value(common.RequestIdKey)})
		return
	}
	if !isValidOIDCScope(scope) || !scopeIsSubset(scope, client.Scope) {
		redirectWithAuthError(c, redirectURI, "invalid_scope", state)
		return
	}

	reqID := c.Request.Context().Value(common.RequestIdKey)
	authReq := &model.AuthRequest{
		ID:                  reqID.(string),
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		State:               state,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	}

	if err := model.CreateAuthRequest(c.Request.Context(), authReq); err != nil {
		common.LogError(c.Request.Context(), "Create auth request: "+err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	userID, err := sessionUserID(c)
	if err != nil {
		redirectToLogin(c, authReq, "")
		return
	}
	deviceID, err := c.Cookie(common.DeviceCookieName)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			redirectToLogin(c, authReq, loginReasonDeviceVerificationRequired)
			return
		}
		common.LogError(c.Request.Context(), "Device cookie error: "+err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "cookie_error"})
		return
	}
	isTrusted, err := model.IsTrustedDevice(userID, deviceID)
	if err != nil {
		common.LogError(c.Request.Context(), "Device trust check error: "+err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	if !isTrusted {
		redirectToLogin(c, authReq, loginReasonDeviceVerificationRequired)
		return
	}
	issueCodeAndRedirect(c, authReq, userID)
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

func issueCodeAndRedirect(c *gin.Context, authReq *model.AuthRequest, userID uint) {
	code := common.GetRandomString(32)
	if err := model.IssueAuthCode(c.Request.Context(), authReq.ID, &model.AuthCode{
		ClientID:            authReq.ClientID,
		UserID:              userID,
		RedirectURI:         authReq.RedirectURI,
		Scope:               authReq.Scope,
		Nonce:               authReq.Nonce,
		CodeChallenge:       authReq.CodeChallenge,
		CodeChallengeMethod: authReq.CodeChallengeMethod,
		Code:                code,
	}); err != nil {
		common.LogError(c.Request.Context(), "Issue auth code: "+err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	parsed, err := url.Parse(authReq.RedirectURI)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	query := parsed.Query()
	query.Set("code", code)
	if authReq.State != "" {
		query.Set("state", authReq.State)
	}
	parsed.RawQuery = query.Encode()
	if c.Request.Method == http.MethodPost && c.NegotiateFormat("text/html", "application/json") == "application/json" {
		c.JSON(http.StatusOK, gin.H{"redirect_to": parsed.String()})
		return
	}
	c.Redirect(http.StatusFound, parsed.String())
}

func LoginHTML(c *gin.Context) {
	c.Redirect(http.StatusFound, loginRedirectURL(c.Query("req_id"), c.Query("reason")))
}
