package controller

import (
	"FGF-idP/common"
	"FGF-idP/model"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestLogoutRevokesAccessAndSession(t *testing.T) {
	env := setupControllerTest(t)
	env.router.POST("/x/logout", Logout)
	session := sessionCookieForUser(t, env)
	access, err := common.GenerateAccessToken(env.user.ID, env.clientID, "openid")
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{"Authorization": "Bearer " + access}
	before := performRequestWithHeaders(t, env.router, "GET", "/x/userinfo", "", "", nil, headers)
	if before.Code != http.StatusOK {
		t.Fatalf("userinfo before logout: %d", before.Code)
	}
	out := performRequestWithHeaders(t, env.router, "POST", "/x/logout", "", "", []*http.Cookie{session}, headers)
	if out.Code != http.StatusOK {
		t.Fatalf("logout: %d %s", out.Code, out.Body.String())
	}
	for _, token := range []string{access, session.Value} {
		if _, err := model.ValidateToken(context.Background(), token); !errors.Is(err, model.ErrTokenRevoked) {
			t.Fatalf("revoked token accepted: %v", err)
		}
	}
	after := performRequestWithHeaders(t, env.router, "GET", "/x/userinfo", "", "", nil, headers)
	if after.Code != http.StatusUnauthorized {
		t.Fatalf("userinfo after logout: %d", after.Code)
	}
	if err := model.SaveDevice(env.deviceID, "test", "127.0.0.1", env.user.ID); err != nil {
		t.Fatal(err)
	}
	auth := performRequest(t, env.router, "GET", authPath(env, "after-logout", "openid"), "", "", []*http.Cookie{
		session, {Name: common.DeviceCookieName, Value: env.deviceID},
	})
	if auth.Code != http.StatusFound || !strings.Contains(auth.Header().Get("Location"), "/login?") {
		t.Fatalf("revoked session used for auth: %d %s", auth.Code, auth.Header().Get("Location"))
	}
	repeated := performRequestWithHeaders(t, env.router, "POST", "/x/logout", "", "", nil, headers)
	if repeated.Code != http.StatusOK {
		t.Fatalf("repeat logout: %d", repeated.Code)
	}
	fresh := sessionCookieForUser(t, env)
	if _, err := model.ValidateToken(context.Background(), fresh.Value); err != nil {
		t.Fatalf("new login incorrectly revoked: %v", err)
	}
}

func TestRevocationPersistsAcrossDatabaseConnections(t *testing.T) {
	env := setupControllerTest(t)
	token := sessionCookieForUser(t, env).Value
	if err := model.RevokeToken(context.Background(), token, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	oldDB := model.DB
	db, err := gorm.Open(sqlite.Open(common.SQLitePath), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	model.DB = db
	t.Cleanup(func() { sqlDB, _ := db.DB(); _ = sqlDB.Close(); model.DB = oldDB })
	if _, err := model.ValidateToken(context.Background(), token); !errors.Is(err, model.ErrTokenRevoked) {
		t.Fatalf("other connection lost revocation: %v", err)
	}
}

func TestRevocationStoreFailureFailsClosed(t *testing.T) {
	env := setupControllerTest(t)
	env.router.POST("/x/logout", Logout)
	session := sessionCookieForUser(t, env)
	if err := model.DB.Migrator().DropTable(&model.RevokedToken{}); err != nil {
		t.Fatal(err)
	}
	if _, err := model.ValidateToken(context.Background(), session.Value); err == nil {
		t.Fatal("validated without revocation store")
	}
	out := performRequest(t, env.router, "POST", "/x/logout", "", "", []*http.Cookie{session})
	if out.Code != http.StatusServiceUnavailable {
		t.Fatalf("logout reported success without revocation: %d", out.Code)
	}
}

func TestAuthCleanupRemovesOnlyExpiredRecords(t *testing.T) {
	setupControllerTest(t)
	now := time.Now()
	for _, row := range []model.RevokedToken{{Hash: "expired", ExpiresAt: now.Add(-time.Hour)}, {Hash: "live", ExpiresAt: now.Add(time.Hour)}} {
		if err := model.DB.Create(&row).Error; err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { model.RunAuthCleanup(ctx); close(done) }()
	deadline := time.After(3 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	defer func() { cancel(); <-done }()
	for {
		var count int64
		if err := model.DB.Model(&model.RevokedToken{}).Where("hash = ?", "expired").Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count == 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("cleanup did not remove expired record")
		case <-tick.C:
		}
	}
	var count int64
	if err := model.DB.Model(&model.RevokedToken{}).Where("hash = ?", "live").Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("live revocation removed: count=%d err=%v", count, err)
	}
}

func TestRevokedTokenCannotBypassWithAlternateEncoding(t *testing.T) {
	env := setupControllerTest(t)
	token := sessionCookieForUser(t, env).Value
	if err := model.RevokeToken(context.Background(), token, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, token[len(token)-1])
	// A 2048-bit RSA signature has four unused bits in the final base64 character.
	alternative := token[:len(token)-1] + string(alphabet[last|1])
	for _, value := range []string{alternative, token + "\r\n"} {
		if _, err := model.ValidateToken(context.Background(), value); err == nil {
			t.Fatal("alternate token encoding bypassed revocation")
		}
	}
}
