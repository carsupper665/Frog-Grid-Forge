package model

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func openAuthTestDB(t *testing.T, path string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(path+"?_pragma=busy_timeout(5000)"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sqlDB.Close() })
	return db
}

func setupAuthTestDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.db")
	previous := DB
	t.Cleanup(func() { DB = previous })
	DB = openAuthTestDB(t, path)
	if err := DB.AutoMigrate(&AuthRequest{}, &AuthCode{}, &RevokedToken{}); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAuthStatePersistsAcrossConnectionsAndRestart(t *testing.T) {
	path := setupAuthTestDB(t)
	ctx := context.Background()
	req := &AuthRequest{ID: "pending", ClientID: "client", RedirectURI: "https://example.com/callback", State: "state", Nonce: "nonce", Scope: "openid", CodeChallenge: "challenge", CodeChallengeMethod: "S256"}
	before := time.Now()
	if err := CreateAuthRequest(ctx, req); err != nil {
		t.Fatal(err)
	}
	if req.ExpiresAt.Before(before.Add(10*time.Minute)) || req.ExpiresAt.After(time.Now().Add(10*time.Minute)) {
		t.Fatal("request TTL must be ten minutes")
	}
	if err := BindAuthVerification(ctx, req.ID, "verification", "device", 1); err != nil {
		t.Fatal(err)
	}
	first := DB
	DB = openAuthTestDB(t, path)
	loaded, err := GetAuthRequestByVerificationToken(ctx, "verification")
	if err != nil || loaded.State != "state" || loaded.Nonce != "nonce" || loaded.CodeChallenge != "challenge" || loaded.EmailVerifyDeviceID == nil || *loaded.EmailVerifyDeviceID != "device" {
		t.Fatalf("other connection lost request: %#v %v", loaded, err)
	}
	sqlDB, _ := first.DB()
	if err := sqlDB.Close(); err != nil {
		t.Fatal(err)
	}
	sqlDB, _ = DB.DB()
	if err := sqlDB.Close(); err != nil {
		t.Fatal(err)
	}
	DB = openAuthTestDB(t, path)
	if _, err := GetAuthRequest(ctx, req.ID); err != nil {
		t.Fatalf("request lost on restart: %v", err)
	}
	code := &AuthCode{Code: "issued", ClientID: req.ClientID, RedirectURI: req.RedirectURI, CodeChallenge: req.CodeChallenge, CodeChallengeMethod: req.CodeChallengeMethod}
	before = time.Now()
	if err := IssueAuthCode(ctx, req.ID, code); err != nil {
		t.Fatal(err)
	}
	if code.ExpiresAt.Before(before.Add(5*time.Minute)) || code.ExpiresAt.After(time.Now().Add(5*time.Minute)) {
		t.Fatal("code TTL must remain five minutes")
	}
	sqlDB, _ = DB.DB()
	if err := sqlDB.Close(); err != nil {
		t.Fatal(err)
	}
	DB = openAuthTestDB(t, path)
	loadedCode, err := GetAuthCode(ctx, code.Code)
	if err != nil {
		t.Fatalf("code lost on restart: %v", err)
	}
	if err := ConsumeAuthCode(ctx, loadedCode); err != nil {
		t.Fatal(err)
	}
	DB = openAuthTestDB(t, path)
	if err := ConsumeAuthCode(ctx, code); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("other node replay: %v", err)
	}
}

func TestAuthStateExpiryAndCleanup(t *testing.T) {
	setupAuthTestDB(t)
	ctx := context.Background()
	now := time.Now()
	token := "expired-token"
	requests := []AuthRequest{{ID: "expired", ExpiresAt: now, EmailVerifyToken: &token}, {ID: "live", ExpiresAt: now.Add(time.Hour)}}
	codes := []AuthCode{{Code: "expired", ExpiresAt: now}, {Code: "live", ExpiresAt: now.Add(time.Hour)}, {Code: "used-live", ExpiresAt: now.Add(time.Hour), IsUsed: true}}
	if err := DB.Create(&requests).Error; err != nil {
		t.Fatal(err)
	}
	if err := DB.Create(&codes).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := GetAuthRequest(ctx, "expired"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("expired request accepted: %v", err)
	}
	if _, err := GetAuthRequestByVerificationToken(ctx, token); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("expired verification accepted: %v", err)
	}
	if err := BindAuthVerification(ctx, "expired", "new-token", "device", 1); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("expired request renewed: %v", err)
	}
	if err := IssueAuthCode(ctx, "expired", &AuthCode{Code: "late"}); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("expired request issued code: %v", err)
	}
	if _, err := GetAuthCode(ctx, "expired"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("expired code accepted: %v", err)
	}
	if err := ConsumeAuthCode(ctx, &codes[0]); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("stale code consumed: %v", err)
	}
	if err := CleanupExpiredAuthState(ctx); err != nil {
		t.Fatal(err)
	}
	var count int64
	if err := DB.Model(&AuthRequest{}).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("requests after cleanup: %d %v", count, err)
	}
	if err := DB.Model(&AuthCode{}).Count(&count).Error; err != nil || count != 2 {
		t.Fatalf("codes after cleanup: %d %v", count, err)
	}
	if _, err := GetAuthRequest(ctx, "live"); err != nil {
		t.Fatal(err)
	}
}

func TestAuthCodeConcurrentConsumeAndBinding(t *testing.T) {
	setupAuthTestDB(t)
	ctx := context.Background()
	code := AuthCode{Code: "race", ClientID: "client", RedirectURI: "callback", CodeChallenge: "challenge", CodeChallengeMethod: "S256", ExpiresAt: time.Now().Add(time.Minute)}
	if err := DB.Create(&code).Error; err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*AuthCode){func(c *AuthCode) { c.ClientID = "wrong" }, func(c *AuthCode) { c.RedirectURI = "wrong" }, func(c *AuthCode) { c.CodeChallenge = "wrong" }, func(c *AuthCode) { c.CodeChallengeMethod = "plain" }} {
		wrong := code
		change(&wrong)
		if err := ConsumeAuthCode(ctx, &wrong); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("wrong binding consumed: %v", err)
		}
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, 16)
	for range 16 {
		wg.Add(1)
		go func() { defer wg.Done(); candidate := code; <-start; results <- ConsumeAuthCode(ctx, &candidate) }()
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("unexpected database failure: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("got %d successful consumers", successes)
	}
}

func TestAuthStateWriteFailuresRollback(t *testing.T) {
	setupAuthTestDB(t)
	ctx := context.Background()
	req := &AuthRequest{ID: "pending"}
	if err := CreateAuthRequest(ctx, req); err != nil {
		t.Fatal(err)
	}
	code := &AuthCode{Code: "duplicate", ExpiresAt: time.Now().Add(time.Hour)}
	if err := DB.Create(code).Error; err != nil {
		t.Fatal(err)
	}
	if err := IssueAuthCode(ctx, req.ID, code); err == nil {
		t.Fatal("duplicate code insert succeeded")
	}
	if _, err := GetAuthRequest(ctx, req.ID); err != nil {
		t.Fatalf("failed insert removed request: %v", err)
	}
	if err := DB.Exec("CREATE TRIGGER reject_consume BEFORE UPDATE ON auth_codes BEGIN SELECT RAISE(ABORT, 'consume failed'); END").Error; err != nil {
		t.Fatal(err)
	}
	if err := ConsumeAuthCode(ctx, code); err == nil {
		t.Fatal("consume error swallowed")
	}
	stored, err := GetAuthCode(ctx, code.Code)
	if err != nil || stored.IsUsed {
		t.Fatalf("failed consume changed code: %#v %v", stored, err)
	}
	if err := DB.Exec("DROP TRIGGER reject_consume").Error; err != nil {
		t.Fatal(err)
	}
	if err := DB.Model(req).Update("expires_at", time.Now().Add(-time.Minute)).Error; err != nil {
		t.Fatal(err)
	}
	if err := DB.Model(code).Update("expires_at", time.Now().Add(-time.Minute)).Error; err != nil {
		t.Fatal(err)
	}
	if err := DB.Exec("CREATE TRIGGER reject_cleanup BEFORE DELETE ON auth_codes BEGIN SELECT RAISE(ABORT, 'cleanup failed'); END").Error; err != nil {
		t.Fatal(err)
	}
	if err := CleanupExpiredAuthState(ctx); err == nil {
		t.Fatal("cleanup error swallowed")
	}
	var count int64
	if err := DB.Model(&AuthRequest{}).Where("id = ?", req.ID).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("failed cleanup did not roll back: %d %v", count, err)
	}
}

func TestAuthStateClosedDatabaseFailsClosed(t *testing.T) {
	setupAuthTestDB(t)
	ctx := context.Background()
	sqlDB, _ := DB.DB()
	if err := sqlDB.Close(); err != nil {
		t.Fatal(err)
	}
	for name, operation := range map[string]func() error{
		"create":            func() error { return CreateAuthRequest(ctx, &AuthRequest{ID: "new"}) },
		"read request":      func() error { _, err := GetAuthRequest(ctx, "new"); return err },
		"read verification": func() error { _, err := GetAuthRequestByVerificationToken(ctx, "token"); return err },
		"bind":              func() error { return BindAuthVerification(ctx, "new", "token", "device", 1) },
		"clear":             func() error { return ConsumeAuthVerification(ctx, "new", "token", "device") },
		"issue":             func() error { return IssueAuthCode(ctx, "new", &AuthCode{Code: "new"}) },
		"read code":         func() error { _, err := GetAuthCode(ctx, "new"); return err },
		"consume":           func() error { return ConsumeAuthCode(ctx, &AuthCode{Code: "new"}) },
		"cleanup":           func() error { return CleanupExpiredAuthState(ctx) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := operation(); err == nil || errors.Is(err, gorm.ErrRecordNotFound) {
				t.Fatalf("DB failure hidden: %v", err)
			}
		})
	}
}

func TestVerificationConsumptionPreservesNewerBinding(t *testing.T) {
	setupAuthTestDB(t)
	ctx := context.Background()
	if err := CreateAuthRequest(ctx, &AuthRequest{ID: "pending"}); err != nil {
		t.Fatal(err)
	}
	if err := BindAuthVerification(ctx, "pending", "new-token", "device", 1); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"old-token", "device"}, {"new-token", "wrong-device"}} {
		if err := ConsumeAuthVerification(ctx, "pending", pair[0], pair[1]); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("consumed wrong binding: %v", err)
		}
	}
	if err := ConsumeAuthVerification(ctx, "pending", "new-token", "device"); err != nil {
		t.Fatal(err)
	}
	if err := ConsumeAuthVerification(ctx, "pending", "new-token", "device"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("replayed verification: %v", err)
	}
}
