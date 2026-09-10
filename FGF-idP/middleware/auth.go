// middleware/auth.go

package middleware

import (
	"FGF-idP/common"
	"FGF-idP/model"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

// RequireRole rejects requests whose stored permission level is below minRole
// and publishes the caller's identity on the gin context.
//
// The role is read from storage on every request. A session cookie lives for 30
// days and revocation is keyed by token hash, so there is no way to invalidate
// one user's outstanding sessions; caching the role anywhere would let a
// demoted or deleted account keep its privileges until the cookie expired.
// Do not "optimise" this lookup away.
func RequireRole(minRole int) gin.HandlerFunc {
	return func(c *gin.Context) {
		role, ok := authenticate(c)
		if !ok {
			return
		}
		if role < minRole {
			abort(c, http.StatusForbidden, "forbidden")
			return
		}
		c.Next()
	}
}

// authenticate resolves the caller once per request. Stacked RequireRole
// handlers reuse the cached result, so a route guarded by two thresholds still
// costs a single lookup.
func authenticate(c *gin.Context) (int, bool) {
	if cached, exists := c.Get(common.CtxRole); exists {
		role, ok := cached.(int)
		return role, ok
	}
	token, err := c.Cookie(common.JwtCookieName)
	if err != nil || token == "" {
		abort(c, http.StatusUnauthorized, "unauthorized")
		return 0, false
	}
	// Any token failure is treated as unauthenticated: failing closed is the
	// safe direction and keeps this path free of error taxonomy.
	userID, err := model.SessionUserID(c.Request.Context(), token)
	if err != nil {
		abort(c, http.StatusUnauthorized, "unauthorized")
		return 0, false
	}
	role, err := model.GetRole(c.Request.Context(), userID)
	if errors.Is(err, model.ErrUserNotFound) {
		abort(c, http.StatusUnauthorized, "unauthorized")
		return 0, false
	}
	if err != nil {
		common.LogError(c.Request.Context(), "session role lookup: "+err.Error())
		abort(c, http.StatusServiceUnavailable, "server_error")
		return 0, false
	}
	c.Set(common.CtxUserID, userID)
	c.Set(common.CtxRole, role)
	return role, true
}

func abort(c *gin.Context, status int, code string) {
	c.Header("Cache-Control", "no-store")
	c.AbortWithStatusJSON(status, gin.H{"error": code})
}
