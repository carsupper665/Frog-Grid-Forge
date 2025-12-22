package controller

import (
	"FGF-idP/common"
	"FGF-idP/model"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type loginReq struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"` // binding:"required"
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
	UserID              *uint // 還沒登入時為 nil
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

func Login(c *gin.Context) {

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

	if responseType != "code" {
		// 如果 redirectURI 合法，建議用 redirect 回去帶 error
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_response_type"})
		return
	}
	if !strings.Contains(scope, "openid") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_scope"})
		return
	}

	if isValid, msg, err := model.ValiClientWithUrl(clientID, redirectURI); !isValid || err != nil {
		common.LogError(c.Request.Context(), "Auth client validation error message: "+msg)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error", "req_id": c.Request.Context().Value(common.RequestIdKey)})
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		}
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
	token, cookieErr := c.Cookie(common.JwtCookieName)
	if cookieErr != nil {
		// 未登入，導向登入頁面
		uri := "/login?=req_id=" + authReq.ID
		setAuthRequest(authReq) // save to cache
		c.Redirect(http.StatusFound, uri)
		return
	}

	payload, jwtErr := common.GetJWTPayload(token)
	if jwtErr != nil {
		// JWT 無效，導向登入頁面
		uri := "/login?=req_id=" + authReq.ID
		setAuthRequest(authReq) // save to cache
		c.Redirect(http.StatusFound, uri)
		return
	}
	authCode := &AuthCode{
		ClientID:            clientID,
		UserID:              payload["user_id"].(uint),
		RedirectURI:         redirectURI,
		Scope:               scope,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Code:                common.GetRandomString(32),
		ExpiresAt:           time.Now().Add(5 * time.Minute),
		IsUsed:              false,
	}

	// Redirect back to client with authorization code
	uri := redirectURI + "?code=" + authCode.Code + "&state=" + state
	setAuthCode(authCode)
	c.Redirect(http.StatusFound, uri)
}

func setAuthRequest(req *AuthRequest) {
	AuthReqsCache.MU.Lock()
	defer AuthReqsCache.MU.Unlock()
	AuthReqsCache.AuthReqs[req.ID] = req
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

func getAuthCode(codeStr string) (*AuthCode, bool) {
	AuthCodesCache.MU.RLock()
	defer AuthCodesCache.MU.RUnlock()
	code, exist := AuthCodesCache.AuthCodes[codeStr]
	return code, exist
}
