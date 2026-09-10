package controller

import (
	"FGF-idP/common"
	"FGF-idP/model"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func setCookie(c *gin.Context, name, value string, maxAge int) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   common.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func issueSessionCookie(c *gin.Context, user model.User) error {
	token, err := common.GenerateSessionToken(user.ID, user.Username)
	if err != nil {
		return err
	}
	setCookie(c, common.JwtCookieName, token, common.SessionCookieExpireSeconds)
	return nil
}

func sessionUserID(c *gin.Context) (uint, error) {
	token, err := c.Cookie(common.JwtCookieName)
	if err != nil {
		return 0, err
	}
	return model.SessionUserID(c.Request.Context(), token)
}

func Logout(c *gin.Context) {
	tokens := make([]string, 0, 2)
	if header := c.GetHeader("Authorization"); header != "" {
		parts := strings.Fields(header)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_token"})
			return
		}
		tokens = append(tokens, parts[1])
	}
	if cookie, err := c.Cookie(common.JwtCookieName); err == nil && cookie != "" {
		if len(tokens) == 0 || tokens[0] != cookie {
			tokens = append(tokens, cookie)
		}
	}
	if len(tokens) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_token"})
		return
	}
	for _, token := range tokens {
		// Verify signatures without rejecting an already revoked token: logout is idempotent.
		payload, err := common.GetJWTPayload(token)
		if errors.Is(err, jwt.ErrTokenExpired) {
			continue
		}
		if err != nil || (payload["typ"] != "session" && payload["typ"] != "access") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_token"})
			return
		}
		exp := time.Unix(int64(payload["exp"].(float64)), 0)
		if err := model.RevokeToken(c.Request.Context(), token, exp); err != nil {
			common.LogError(c.Request.Context(), "Token revocation failed: "+err.Error())
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "server_error"})
			return
		}
	}
	setCookie(c, common.JwtCookieName, "", -1)
	c.JSON(http.StatusOK, gin.H{"message": "logged_out"})
}
