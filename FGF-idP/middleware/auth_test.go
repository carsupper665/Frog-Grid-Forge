package middleware

import (
	"FGF-idP/common"
	"FGF-idP/model"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func setupAuthTest(t *testing.T) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.RevokedToken{}); err != nil {
		t.Fatalf("migrate test db: %v", err)
	}

	prevDB, prevPriv, prevPub, prevIssuer := model.DB, common.RSAPrivateKey, common.RSAPublicKey, common.Issuer
	model.DB = db
	common.RSAPrivateKey = key
	common.RSAPublicKey = &key.PublicKey
	common.Issuer = "http://127.0.0.1:18080"
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
		model.DB, common.RSAPrivateKey, common.RSAPublicKey, common.Issuer = prevDB, prevPriv, prevPub, prevIssuer
	})
}

func addAuthUser(t *testing.T, username string, role int) model.User {
	t.Helper()
	user := model.User{Username: username, Email: username + "@example.com", Password: "x", Salt: "y", Role: role}
	if err := model.DB.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user
}

func sessionToken(t *testing.T, user model.User) string {
	t.Helper()
	token, err := common.GenerateSessionToken(user.ID, user.Username)
	if err != nil {
		t.Fatalf("generate session token: %v", err)
	}
	return token
}

// guardedRouter mounts the gates under test and reports what the handler saw.
func guardedRouter(thresholds ...int) (*gin.Engine, *actorSeen) {
	seen := &actorSeen{}
	router := gin.New()
	group := router.Group("/")
	for _, threshold := range thresholds {
		group.Use(RequireRole(threshold))
	}
	group.GET("guarded", func(c *gin.Context) {
		seen.userID, seen.hasUserID = c.Get(common.CtxUserID)
		seen.role, seen.hasRole = c.Get(common.CtxRole)
		c.Status(http.StatusOK)
	})
	return router, seen
}

type actorSeen struct {
	userID, role       any
	hasUserID, hasRole bool
}

func callGuarded(router *gin.Engine, token string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "/guarded", nil)
	if token != "" {
		request.AddCookie(&http.Cookie{Name: common.JwtCookieName, Value: token})
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

func TestRequireRoleRejectsBadSessions(t *testing.T) {
	setupAuthTest(t)
	user := addAuthUser(t, "auth-admin", common.RoleAdminUser)

	revoked := sessionToken(t, user)
	if err := model.RevokeToken(context.Background(), revoked, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("revoke token: %v", err)
	}

	for _, tc := range []struct {
		name, token string
	}{
		{name: "no cookie", token: ""},
		{name: "malformed token", token: "not-a-jwt"},
		{name: "revoked token", token: revoked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			router, _ := guardedRouter(common.RoleAdminUser)
			if resp := callGuarded(router, tc.token); resp.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d body=%s", resp.Code, resp.Body.String())
			}
		})
	}
}

func TestRequireRolePublishesIdentity(t *testing.T) {
	setupAuthTest(t)
	user := addAuthUser(t, "auth-root", common.RoleRootUser)

	router, seen := guardedRouter(common.RoleAdminUser)
	if resp := callGuarded(router, sessionToken(t, user)); resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	id, ok := seen.userID.(uint)
	if !seen.hasUserID || !ok || id != user.ID {
		t.Fatalf("expected uint user id %d on the context, got %#v", user.ID, seen.userID)
	}
	role, ok := seen.role.(int)
	if !seen.hasRole || !ok || role != common.RoleRootUser {
		t.Fatalf("expected int role %d on the context, got %#v", common.RoleRootUser, seen.role)
	}
}

func TestRequireRoleEnforcesThreshold(t *testing.T) {
	setupAuthTest(t)
	common1 := addAuthUser(t, "auth-plain", common.RoleCommonUser)
	admin := addAuthUser(t, "auth-adm2", common.RoleAdminUser)

	router, _ := guardedRouter(common.RoleAdminUser)
	if resp := callGuarded(router, sessionToken(t, common1)); resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", resp.Code, resp.Body.String())
	}
	if resp := callGuarded(router, sessionToken(t, admin)); resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
}

// TestRequireRoleStacks covers the /x/admin/clients shape, where a root gate
// sits on top of the admin gate the parent group already applied.
func TestRequireRoleStacks(t *testing.T) {
	setupAuthTest(t)
	admin := addAuthUser(t, "auth-adm3", common.RoleAdminUser)
	root := addAuthUser(t, "auth-root2", common.RoleRootUser)

	router, _ := guardedRouter(common.RoleAdminUser, common.RoleRootUser)
	if resp := callGuarded(router, sessionToken(t, admin)); resp.Code != http.StatusForbidden {
		t.Fatalf("admin passed a root gate: %d body=%s", resp.Code, resp.Body.String())
	}
	if resp := callGuarded(router, sessionToken(t, root)); resp.Code != http.StatusOK {
		t.Fatalf("root blocked by stacked gates: %d body=%s", resp.Code, resp.Body.String())
	}
}

// TestRequireRoleFailsClosedOnStorageError distinguishes "cannot tell" from
// "not allowed": an unreachable store must not read as a missing account.
func TestRequireRoleFailsClosedOnStorageError(t *testing.T) {
	setupAuthTest(t)
	user := addAuthUser(t, "auth-adm4", common.RoleAdminUser)
	token := sessionToken(t, user)
	if err := model.DB.Migrator().DropTable(&model.User{}); err != nil {
		t.Fatalf("drop users table: %v", err)
	}

	router, _ := guardedRouter(common.RoleAdminUser)
	if resp := callGuarded(router, token); resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d body=%s", resp.Code, resp.Body.String())
	}
}
