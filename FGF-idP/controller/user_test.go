package controller

import (
	"FGF-idP/common"
	"FGF-idP/middleware"
	"FGF-idP/model"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type controllerTestEnv struct {
	router       *gin.Engine
	clientID     string
	clientSecret string
	redirectURI  string
	username     string
	password     string
	user         model.User
	deviceID     string
}

func TestAuthRedirectsToLoginWithReqID(t *testing.T) {
	env := setupControllerTest(t)

	resp := performRequest(t, env.router, http.MethodGet, authPath(env, "state-auth", "openid profile"), "", "", nil)
	if resp.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d body=%s", resp.Code, resp.Body.String())
	}

	location := resp.Header().Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if parsed.Scheme != "http" || parsed.Host != "127.0.0.1:18081" || parsed.Path != "/login" {
		t.Fatalf("expected login redirect, got %q", location)
	}

	reqID := parsed.Query().Get("req_id")
	if reqID == "" {
		t.Fatalf("expected req_id in redirect, got %q", location)
	}
	if _, ok := getAuthRequest(reqID); !ok {
		t.Fatalf("expected auth request %q to be cached", reqID)
	}
}

func TestAuthRejectsInvalidScope(t *testing.T) {
	env := setupControllerTest(t)

	for _, tc := range []struct {
		name  string
		scope string
	}{
		{name: "missing openid", scope: "profile"},
		{name: "offline_access unsupported", scope: "openid offline_access"},
		{name: "admin unsupported", scope: "openid admin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := performRequest(t, env.router, http.MethodGet, authPath(env, "state-bad-scope", tc.scope), "", "", nil)
			if resp.Code != http.StatusFound {
				t.Fatalf("expected 302, got %d body=%s", resp.Code, resp.Body.String())
			}
			parsed, err := url.Parse(resp.Header().Get("Location"))
			if err != nil {
				t.Fatalf("parse redirect: %v", err)
			}
			if parsed.Query().Get("error") != "invalid_scope" {
				t.Fatalf("expected invalid_scope redirect, got %q", resp.Header().Get("Location"))
			}
			if parsed.Query().Get("state") != "state-bad-scope" {
				t.Fatalf("expected state to round-trip, got %q", resp.Header().Get("Location"))
			}
		})
	}
}

func TestAuthDirectCodeWithValidSessionAndTrustedDevice(t *testing.T) {
	env := setupControllerTest(t)
	if err := model.SaveDevice(env.deviceID, "go-test", "127.0.0.1", env.user.ID); err != nil {
		t.Fatalf("save device: %v", err)
	}

	resp := performRequest(t, env.router, http.MethodGet, authPath(env, "state-session", "openid profile"), "", "", []*http.Cookie{
		sessionCookieForUser(t, env),
		{Name: common.DeviceCookieName, Value: env.deviceID},
	})
	if resp.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d body=%s", resp.Code, resp.Body.String())
	}
	parsed, err := url.Parse(resp.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatalf("expected code in redirect, got %q", resp.Header().Get("Location"))
	}
	if parsed.Query().Get("state") != "state-session" {
		t.Fatalf("expected state to round-trip, got %q", resp.Header().Get("Location"))
	}
	if _, ok := getAuthCode(code); !ok {
		t.Fatalf("expected auth code %q to be cached", code)
	}
}

func TestAuthRedirectsToLoginWhenSessionValidButDeviceUntrusted(t *testing.T) {
	env := setupControllerTest(t)

	resp := performRequest(t, env.router, http.MethodGet, authPath(env, "state-untrusted", "openid profile"), "", "", []*http.Cookie{
		sessionCookieForUser(t, env),
		{Name: common.DeviceCookieName, Value: "untrusted-device"},
	})
	if resp.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d body=%s", resp.Code, resp.Body.String())
	}
	parsed, err := url.Parse(resp.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if parsed.Path != "/login" {
		t.Fatalf("expected login redirect, got %q", resp.Header().Get("Location"))
	}
	if parsed.Query().Get("reason") != loginReasonDeviceVerificationRequired {
		t.Fatalf("expected device verification reason, got %q", resp.Header().Get("Location"))
	}
	if parsed.Query().Get("req_id") == "" {
		t.Fatalf("expected req_id in redirect, got %q", resp.Header().Get("Location"))
	}
}

func TestAuthRedirectsToLoginWhenSessionInvalidEvenWithTrustedDevice(t *testing.T) {
	env := setupControllerTest(t)
	if err := model.SaveDevice(env.deviceID, "go-test", "127.0.0.1", env.user.ID); err != nil {
		t.Fatalf("save device: %v", err)
	}

	resp := performRequest(t, env.router, http.MethodGet, authPath(env, "state-invalid-session", "openid profile"), "", "", []*http.Cookie{
		{Name: common.JwtCookieName, Value: "not-a-valid-session"},
		{Name: common.DeviceCookieName, Value: env.deviceID},
	})
	if resp.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d body=%s", resp.Code, resp.Body.String())
	}
	parsed, err := url.Parse(resp.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if parsed.Path != "/login" || parsed.Query().Get("req_id") == "" {
		t.Fatalf("expected login redirect with req_id, got %q", resp.Header().Get("Location"))
	}
}

func TestLoginRejectsInvalidReqID(t *testing.T) {
	env := setupControllerTest(t)
	body := fmt.Sprintf(`{"username":"%s","password":"%s","req_id":"missing-req"}`,
		env.username,
		env.password,
	)

	resp := performRequest(t, env.router, http.MethodPost, "/x/login", body, "application/json", nil)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", resp.Code, resp.Body.String())
	}
	assertJSONError(t, resp, "invalid_req_id")
}

func TestLoginRedirectsWithCodeForKnownDevice(t *testing.T) {
	env := setupControllerTest(t)
	if err := model.SaveDevice(env.deviceID, "go-test", "127.0.0.1", env.user.ID); err != nil {
		t.Fatalf("save device: %v", err)
	}

	reqID := startAuthorization(t, env, "state-login")
	body := fmt.Sprintf(`{"username":"%s","password":"%s","req_id":"%s"}`,
		env.username,
		env.password,
		reqID,
	)

	resp := performRequest(t, env.router, http.MethodPost, "/x/login", body, "application/json", []*http.Cookie{{
		Name:  common.DeviceCookieName,
		Value: env.deviceID,
	}})
	if resp.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d body=%s", resp.Code, resp.Body.String())
	}

	location := resp.Header().Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatalf("expected code in redirect, got %q", location)
	}
	if parsed.Query().Get("state") != "state-login" {
		t.Fatalf("expected state to round-trip, got %q", location)
	}
	if _, ok := getAuthCode(code); !ok {
		t.Fatalf("expected auth code %q to be cached", code)
	}
	if _, ok := getAuthRequest(reqID); ok {
		t.Fatalf("expected auth request %q to be removed after code issue", reqID)
	}
	if !hasSetCookie(resp, common.JwtCookieName) {
		t.Fatalf("expected %s cookie to be set", common.JwtCookieName)
	}
}

func TestLoginReturnsVerificationRequiredForNewDevice(t *testing.T) {
	env := setupControllerTest(t)
	reqID := startAuthorization(t, env, "state-new-device")
	body := fmt.Sprintf(`{"username":"%s","password":"%s","req_id":"%s"}`,
		env.username,
		env.password,
		reqID,
	)

	resp := performRequest(t, env.router, http.MethodPost, "/x/login", body, "application/json", nil)
	if resp.Code != http.StatusNonAuthoritativeInfo {
		t.Fatalf("expected 203, got %d body=%s", resp.Code, resp.Body.String())
	}
	if !hasSetCookie(resp, common.DeviceCookieName) {
		t.Fatalf("expected %s cookie to be set", common.DeviceCookieName)
	}
	deviceID, ok := setCookieValue(resp, common.DeviceCookieName)
	if !ok || deviceID == "" {
		t.Fatalf("expected %s cookie value", common.DeviceCookieName)
	}
	authReq, ok := getAuthRequest(reqID)
	if !ok {
		t.Fatalf("expected auth request %q to remain cached", reqID)
	}
	if authReq.EmailVerifyDeviceID == nil || *authReq.EmailVerifyDeviceID != deviceID {
		t.Fatalf("expected verification token bound to new device %q, got %#v", deviceID, authReq.EmailVerifyDeviceID)
	}
	if !hasSetCookie(resp, common.JwtCookieName) {
		t.Fatalf("expected %s cookie to be set", common.JwtCookieName)
	}
	assertBodyContains(t, resp, "new_device_detected")
}

func TestLoginReturnsVerificationRequiredForExistingUntrustedDevice(t *testing.T) {
	env := setupControllerTest(t)
	reqID := startAuthorization(t, env, "state-existing-untrusted")
	body := fmt.Sprintf(`{"username":"%s","password":"%s","req_id":"%s"}`,
		env.username,
		env.password,
		reqID,
	)

	resp := performRequest(t, env.router, http.MethodPost, "/x/login", body, "application/json", []*http.Cookie{{
		Name:  common.DeviceCookieName,
		Value: "existing-but-untrusted-device",
	}})
	if resp.Code != http.StatusNonAuthoritativeInfo {
		t.Fatalf("expected 203, got %d body=%s", resp.Code, resp.Body.String())
	}
	authReq, ok := getAuthRequest(reqID)
	if !ok {
		t.Fatalf("expected auth request %q to remain cached", reqID)
	}
	if authReq.EmailVerifyDeviceID == nil || *authReq.EmailVerifyDeviceID != "existing-but-untrusted-device" {
		t.Fatalf("expected verification token bound to existing device, got %#v", authReq.EmailVerifyDeviceID)
	}
	assertBodyContains(t, resp, "device_verification_required")
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	env := setupControllerTest(t)
	reqID := startAuthorization(t, env, "state-wrong-password")
	body := fmt.Sprintf(`{"username":"%s","password":"wrong-password","req_id":"%s"}`,
		env.username,
		reqID,
	)

	resp := performRequest(t, env.router, http.MethodPost, "/x/login", body, "application/json", nil)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body=%s", resp.Code, resp.Body.String())
	}
	assertJSONError(t, resp, "invalid_credentials")
}

func TestVerifyRejectsMissingToken(t *testing.T) {
	env := setupControllerTest(t)

	resp := performRequest(t, env.router, http.MethodGet, "/x/verify", "", "", nil)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", resp.Code, resp.Body.String())
	}
	assertJSONError(t, resp, "missing_token")
}

func TestVerifyRedirectsWithCodeForValidToken(t *testing.T) {
	env := setupControllerTest(t)
	token, err := common.GenEmailSignedToken(env.user.Email)
	if err != nil {
		t.Fatalf("generate email token: %v", err)
	}

	authReq := &AuthRequest{
		ID:          "verify-req",
		ClientID:    env.clientID,
		RedirectURI: env.redirectURI,
		Scope:       "openid profile",
		State:       "verify-state",
	}
	setAuthRequest(authReq)
	if err := setAuthEmailToken(authReq.ID, token, "verify-device"); err != nil {
		t.Fatalf("set auth email token: %v", err)
	}

	resp := performRequest(t, env.router, http.MethodGet, "/x/verify?t="+url.QueryEscape(token), "", "", []*http.Cookie{{
		Name:  common.DeviceCookieName,
		Value: "verify-device",
	}})
	if resp.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d body=%s", resp.Code, resp.Body.String())
	}

	location := resp.Header().Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatalf("expected code in redirect, got %q", location)
	}
	if parsed.Query().Get("state") != "verify-state" {
		t.Fatalf("expected state to round-trip, got %q", location)
	}
	if _, ok := getAuthCode(code); !ok {
		t.Fatalf("expected auth code %q to be cached", code)
	}
	deviceExists, err := model.IsTrustedDevice(env.user.ID, "verify-device")
	if err != nil {
		t.Fatalf("check device: %v", err)
	}
	if !deviceExists {
		t.Fatal("expected verified device to be stored")
	}
	if !hasSetCookie(resp, common.JwtCookieName) {
		t.Fatalf("expected %s cookie to be set", common.JwtCookieName)
	}
}

func TestVerifyRejectsDifferentDeviceAndAcceptsOriginal(t *testing.T) {
	env := setupControllerTest(t)
	token, err := common.GenEmailSignedToken(env.user.Email)
	if err != nil {
		t.Fatalf("generate email token: %v", err)
	}

	authReq := &AuthRequest{
		ID:          "verify-bound-req",
		ClientID:    env.clientID,
		RedirectURI: env.redirectURI,
		Scope:       "openid profile",
		State:       "bound-state",
	}
	setAuthRequest(authReq)
	if err := setAuthEmailToken(authReq.ID, token, "original-device"); err != nil {
		t.Fatalf("set auth email token: %v", err)
	}

	wrongDeviceResp := performRequest(t, env.router, http.MethodGet, "/x/verify?t="+url.QueryEscape(token), "", "", []*http.Cookie{{
		Name:  common.DeviceCookieName,
		Value: "different-device",
	}})
	if wrongDeviceResp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", wrongDeviceResp.Code, wrongDeviceResp.Body.String())
	}
	assertJSONError(t, wrongDeviceResp, "invalid_device")

	originalDeviceResp := performRequest(t, env.router, http.MethodGet, "/x/verify?t="+url.QueryEscape(token), "", "", []*http.Cookie{{
		Name:  common.DeviceCookieName,
		Value: "original-device",
	}})
	if originalDeviceResp.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d body=%s", originalDeviceResp.Code, originalDeviceResp.Body.String())
	}
	parsed, err := url.Parse(originalDeviceResp.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if parsed.Query().Get("code") == "" || parsed.Query().Get("state") != "bound-state" {
		t.Fatalf("expected code and original state, got %q", originalDeviceResp.Header().Get("Location"))
	}
}

func TestTokenReturnsTokensForValidAuthorizationCode(t *testing.T) {
	env := setupControllerTest(t)
	if err := model.SaveDevice(env.deviceID, "go-test", "127.0.0.1", env.user.ID); err != nil {
		t.Fatalf("save device: %v", err)
	}

	reqID := startAuthorization(t, env, "state-token")
	code := loginKnownDevice(t, env, reqID)
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {env.redirectURI},
		"client_id":     {env.clientID},
		"client_secret": {env.clientSecret},
	}

	resp := performRequest(t, env.router, http.MethodPost, "/x/token", form.Encode(), "application/x-www-form-urlencoded", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	data := decodeJSONMap(t, resp)
	for _, key := range []string{"access_token", "id_token", "token_type", "expires_in", "scope"} {
		if _, ok := data[key]; !ok {
			t.Fatalf("expected %q in token response: %v", key, data)
		}
	}
	if data["scope"] != "openid profile" {
		t.Fatalf("expected scope to round-trip, got %#v", data["scope"])
	}
	if _, ok := data["refresh_token"]; ok {
		t.Fatalf("did not expect refresh_token in response: %v", data)
	}
	assertJWTHeaderKid(t, data["access_token"].(string), common.ActiveKeyID)
	assertJWTHeaderKid(t, data["id_token"].(string), common.ActiveKeyID)
	authCode, ok := getAuthCode(code)
	if !ok {
		t.Fatalf("expected auth code %q to remain cached for used-check", code)
	}
	if !authCode.IsUsed {
		t.Fatal("expected auth code to be marked used")
	}
}

func TestUserInfoReturnsClaimsForValidAccessToken(t *testing.T) {
	env := setupControllerTest(t)
	accessToken, err := common.GenerateAccessToken(env.user.ID, env.clientID, "openid profile email")
	if err != nil {
		t.Fatalf("generate access token: %v", err)
	}

	resp := performRequestWithHeaders(t, env.router, http.MethodGet, "/x/userinfo", "", "", nil, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	data := decodeJSONMap(t, resp)
	if data["sub"] != fmt.Sprint(env.user.ID) || data["email"] != env.user.Email || data["name"] != env.user.DisplayName {
		t.Fatalf("unexpected userinfo claims: %v", data)
	}
	if data["preferred_username"] != env.user.Username {
		t.Fatalf("expected preferred_username, got %v", data)
	}
}

func TestUserInfoRejectsInvalidTokenWithAuthenticateHeader(t *testing.T) {
	env := setupControllerTest(t)

	resp := performRequestWithHeaders(t, env.router, http.MethodGet, "/x/userinfo", "", "", nil, map[string]string{
		"Authorization": "Bearer invalid-token",
	})
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body=%s", resp.Code, resp.Body.String())
	}
	if resp.Header().Get("WWW-Authenticate") != `Bearer error="invalid_token"` {
		t.Fatalf("unexpected WWW-Authenticate header: %q", resp.Header().Get("WWW-Authenticate"))
	}
}

func TestUserInfoRejectsSessionAndIDTokens(t *testing.T) {
	env := setupControllerTest(t)
	sessionToken, err := common.GenerateSessionToken(env.user.ID, env.user.Username)
	if err != nil {
		t.Fatalf("generate session token: %v", err)
	}
	idToken, err := common.GenerateIDToken(env.user.ID, env.clientID, "nonce")
	if err != nil {
		t.Fatalf("generate id token: %v", err)
	}

	for name, token := range map[string]string{
		"session": sessionToken,
		"id":      idToken,
	} {
		t.Run(name, func(t *testing.T) {
			resp := performRequestWithHeaders(t, env.router, http.MethodGet, "/x/userinfo", "", "", nil, map[string]string{
				"Authorization": "Bearer " + token,
			})
			if resp.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d body=%s", resp.Code, resp.Body.String())
			}
			if resp.Header().Get("WWW-Authenticate") != `Bearer error="invalid_token"` {
				t.Fatalf("unexpected WWW-Authenticate header: %q", resp.Header().Get("WWW-Authenticate"))
			}
		})
	}
}

func TestUserInfoRequiresOpenIDScope(t *testing.T) {
	env := setupControllerTest(t)
	accessToken, err := common.GenerateAccessToken(env.user.ID, env.clientID, "profile email")
	if err != nil {
		t.Fatalf("generate access token: %v", err)
	}

	resp := performRequestWithHeaders(t, env.router, http.MethodGet, "/x/userinfo", "", "", nil, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestTokenRejectsInvalidGrant(t *testing.T) {
	env := setupControllerTest(t)
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"missing-code"},
		"redirect_uri":  {env.redirectURI},
		"client_id":     {env.clientID},
		"client_secret": {env.clientSecret},
	}

	resp := performRequest(t, env.router, http.MethodPost, "/x/token", form.Encode(), "application/x-www-form-urlencoded", nil)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", resp.Code, resp.Body.String())
	}
	assertJSONError(t, resp, "invalid_grant")
}

func setupControllerTest(t *testing.T) *controllerTestEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	closeTestDB(t)
	t.Cleanup(func() {
		closeTestDB(t)
	})

	tempDir := t.TempDir()
	privPath := filepath.Join(tempDir, "private_key.pem")
	pubPath := filepath.Join(tempDir, "public_key.pem")
	writeTestKeyPair(t, privPath, pubPath)

	username := "root-user"
	password := "correct-horse-battery-staple"
	clientID := "test-client"
	clientSecret := "test-client-secret"
	redirectURI := "http://127.0.0.1:3210/callback"

	t.Setenv("SESSION_SECRET", "test-session-secret")
	t.Setenv("CRYPTO_SECRET", "test-crypto-secret")
	t.Setenv("HMAC_SECRET", "test-hmac-secret")
	t.Setenv("CREATE_ROOT_USER", "true")
	t.Setenv("ROOT_USER_EMAIL", "root@example.com")
	t.Setenv("ROOT_USER_PASSWORD", password)
	t.Setenv("ROOT_USER_NAME", username)
	t.Setenv("BACKEND_BASE_URL", "http://127.0.0.1:18080")
	t.Setenv("FRONTEND_BASE_URL", "http://127.0.0.1:18081")
	t.Setenv("PORT", "18080")
	t.Setenv("DEBUG", "false")
	t.Setenv("SQL_DSN", "")
	t.Setenv("SQLITE_PATH", fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "-")))
	t.Setenv("PRIV_KEY_PATH", privPath)
	t.Setenv("PUB_KEY_PATH", pubPath)
	t.Setenv("SMTP_SERVER", "")
	t.Setenv("SMTP_ACCOUNT", "")
	t.Setenv("SMTP_FROM", "")
	t.Setenv("SMTP_TOKEN", "")

	common.LoadEnv()
	common.InitLogger()
	common.Issuer = common.GetEnvOrDefaultString("BACKEND_BASE_URL", "http://127.0.0.1:18080")
	if err := model.InitDB(); err != nil {
		t.Fatalf("init db: %v", err)
	}
	InitAuthCache()
	upsertTestClient(t, clientID, clientSecret, redirectURI)

	user, err := model.GetUserByName(username)
	if err != nil {
		t.Fatalf("load test user: %v", err)
	}

	r := gin.New()
	r.Use(middleware.RequestId())
	root := r.Group("/x")
	root.GET("/auth", Auth)
	root.POST("/login", Login)
	root.GET("/verify", EmailVerify)
	root.POST("/token", Token)
	root.GET("/userinfo", UserInfo)

	return &controllerTestEnv{
		router:       r,
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURI:  redirectURI,
		username:     username,
		password:     password,
		user:         user,
		deviceID:     "known-device-id",
	}
}

func closeTestDB(t *testing.T) {
	t.Helper()
	if model.DB == nil {
		return
	}
	sqlDB, err := model.DB.DB()
	if err != nil {
		return
	}
	_ = sqlDB.Close()
	model.DB = nil
	InitAuthCache()
}

func writeTestKeyPair(t *testing.T, privatePath, publicPath string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err := os.WriteFile(privatePath, privatePEM, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicDER,
	})
	if err := os.WriteFile(publicPath, publicPEM, 0o644); err != nil {
		t.Fatalf("write public key: %v", err)
	}
}

func upsertTestClient(t *testing.T, clientID, clientSecret, redirectURI string) {
	t.Helper()
	secretHash, err := common.Password2Hash(clientSecret)
	if err != nil {
		t.Fatalf("hash client secret: %v", err)
	}
	redirectURIs, err := json.Marshal([]string{redirectURI})
	if err != nil {
		t.Fatalf("marshal redirect uris: %v", err)
	}
	grantTypes, err := json.Marshal([]string{"authorization_code"})
	if err != nil {
		t.Fatalf("marshal grant types: %v", err)
	}
	responseTypes, err := json.Marshal([]string{"code"})
	if err != nil {
		t.Fatalf("marshal response types: %v", err)
	}
	client := model.Client{
		ClientID:      clientID,
		SecretHash:    secretHash,
		RedirectURIs:  datatypes.JSON(redirectURIs),
		Scope:         "openid profile email",
		GrantTypes:    datatypes.JSON(grantTypes),
		ResponseTypes: datatypes.JSON(responseTypes),
	}
	if err := model.DB.Session(&gorm.Session{FullSaveAssociations: true}).Save(&client).Error; err != nil {
		t.Fatalf("save test client: %v", err)
	}
}

func authPath(env *controllerTestEnv, state, scope string) string {
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {env.clientID},
		"redirect_uri":  {env.redirectURI},
		"scope":         {scope},
		"state":         {state},
	}
	return "/x/auth?" + params.Encode()
}

func startAuthorization(t *testing.T, env *controllerTestEnv, state string) string {
	t.Helper()
	resp := performRequest(t, env.router, http.MethodGet, authPath(env, state, "openid profile"), "", "", nil)
	if resp.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d body=%s", resp.Code, resp.Body.String())
	}
	parsed, err := url.Parse(resp.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	reqID := parsed.Query().Get("req_id")
	if reqID == "" {
		t.Fatalf("expected req_id in redirect, got %q", resp.Header().Get("Location"))
	}
	return reqID
}

func loginKnownDevice(t *testing.T, env *controllerTestEnv, reqID string) string {
	t.Helper()
	body := fmt.Sprintf(`{"username":"%s","password":"%s","req_id":"%s"}`,
		env.username,
		env.password,
		reqID,
	)
	resp := performRequest(t, env.router, http.MethodPost, "/x/login", body, "application/json", []*http.Cookie{{
		Name:  common.DeviceCookieName,
		Value: env.deviceID,
	}})
	if resp.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d body=%s", resp.Code, resp.Body.String())
	}
	parsed, err := url.Parse(resp.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatalf("expected code in redirect, got %q", resp.Header().Get("Location"))
	}
	return code
}

func performRequest(t *testing.T, router *gin.Engine, method, target, body, contentType string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	return performRequestWithHeaders(t, router, method, target, body, contentType, cookies, nil)
}

func performRequestWithHeaders(t *testing.T, router *gin.Engine, method, target, body, contentType string, cookies []*http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func sessionCookieForUser(t *testing.T, env *controllerTestEnv) *http.Cookie {
	t.Helper()
	token, err := common.GenerateSessionToken(env.user.ID, env.user.Username)
	if err != nil {
		t.Fatalf("generate session token: %v", err)
	}
	return &http.Cookie{Name: common.JwtCookieName, Value: token}
}

func hasSetCookie(resp *httptest.ResponseRecorder, name string) bool {
	_, ok := setCookieValue(resp, name)
	return ok
}

func setCookieValue(resp *httptest.ResponseRecorder, name string) (string, bool) {
	for _, cookie := range resp.Result().Cookies() {
		if cookie.Name == name {
			return cookie.Value, true
		}
	}
	return "", false
}

func assertJWTHeaderKid(t *testing.T, token, want string) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		t.Fatalf("invalid jwt format")
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode jwt header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		t.Fatalf("unmarshal jwt header: %v", err)
	}
	if header["kid"] != want {
		t.Fatalf("expected kid %q, got %#v", want, header["kid"])
	}
}

func decodeJSONMap(t *testing.T, resp *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var data map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &data); err != nil {
		t.Fatalf("decode json: %v body=%s", err, resp.Body.String())
	}
	return data
}

func assertJSONError(t *testing.T, resp *httptest.ResponseRecorder, want string) {
	t.Helper()
	data := decodeJSONMap(t, resp)
	if data["error"] != want {
		t.Fatalf("expected error %q, got %#v", want, data["error"])
	}
}

func assertBodyContains(t *testing.T, resp *httptest.ResponseRecorder, want string) {
	t.Helper()
	if !strings.Contains(resp.Body.String(), want) {
		t.Fatalf("expected body to contain %q, got %s", want, resp.Body.String())
	}
}
