package controller

import (
	"FGF-idP/common"
	"FGF-idP/model"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type tokenReq struct {
	GrantType    string `form:"grant_type" binding:"required"`
	Code         string `form:"code" binding:"required"`
	RedirectURI  string `form:"redirect_uri" binding:"required"`
	ClientID     string `form:"client_id" binding:"required"`
	ClientSecret string `form:"client_secret"`
	CodeVerifier string `form:"code_verifier"`
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
	if err != nil || !isValid {
		common.LogError(c.Request.Context(), "Token validation error: "+msg)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}

	authCode, err := verifyAuthCodeInternal(c.Request.Context(), req.Code, req.ClientID, req.RedirectURI, req.CodeVerifier)
	if err != nil {
		common.LogError(c.Request.Context(), "Token verifyAuthCodeInternal error: "+err.Error())
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		}
		return
	}
	accessToken, idToken, err := issueTokens(authCode.UserID, authCode.ClientID, authCode.Scope, authCode.Nonce)
	if err != nil {
		common.LogError(c.Request.Context(), "Token issueTokens error: "+err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"access_token": accessToken,
		"id_token":     idToken,
		"token_type":   "Bearer",
		"expires_in":   common.AccessTokenExpireSeconds,
		"scope":        authCode.Scope,
	})
}

func UserInfo(c *gin.Context) {
	parts := strings.Fields(c.GetHeader("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		unauthorizedUserInfo(c)
		return
	}
	payload, err := model.ValidateToken(c.Request.Context(), parts[1])
	if err != nil || payload["typ"] != "access" {
		unauthorizedUserInfo(c)
		return
	}
	aud, ok := payload["aud"].(string)
	if !ok || aud == "" {
		unauthorizedUserInfo(c)
		return
	}
	clientExists, err := model.ClientExists(aud)
	if err != nil || !clientExists {
		unauthorizedUserInfo(c)
		return
	}
	scope, ok := payload["scope"].(string)
	if !ok || !scopeIncludes(scope, "openid") {
		unauthorizedUserInfo(c)
		return
	}
	sub, ok := payload["sub"].(string)
	if !ok || sub == "" {
		unauthorizedUserInfo(c)
		return
	}
	uid, err := strconv.ParseUint(sub, 10, 32)
	if err != nil {
		unauthorizedUserInfo(c)
		return
	}
	user, err := model.GetUserByID(uint(uid))
	if err != nil {
		unauthorizedUserInfo(c)
		return
	}
	name := user.DisplayName
	if name == "" {
		name = user.Username
	}
	c.JSON(http.StatusOK, gin.H{
		"sub":                sub,
		"email":              user.Email,
		"name":               name,
		"preferred_username": user.Username,
		"role":               user.Role,
	})
}

func unauthorizedUserInfo(c *gin.Context) {
	c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
	c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
}

func issueTokens(userID uint, clientID, scope, nonce string) (string, string, error) {
	accessToken, err := common.GenerateAccessToken(userID, clientID, scope)
	if err != nil {
		return "", "", err
	}
	idToken, err := common.GenerateIDToken(userID, clientID, nonce)
	return accessToken, idToken, err
}

func verifyAuthCodeInternal(ctx context.Context, value, clientID, redirectURI, codeVerifier string) (*model.AuthCode, error) {
	code, err := model.GetAuthCode(ctx, value)
	if err != nil {
		return nil, err
	}
	if code.ClientID != clientID || code.RedirectURI != redirectURI || code.IsUsed {
		return nil, gorm.ErrRecordNotFound
	}
	if code.CodeChallenge != "" && !common.VerifyPKCE(codeVerifier, code.CodeChallenge, code.CodeChallengeMethod) {
		return nil, fmt.Errorf("invalid code verifier: %w", gorm.ErrRecordNotFound)
	}
	if err := model.ConsumeAuthCode(ctx, code); err != nil {
		return nil, err
	}
	return code, nil
}
