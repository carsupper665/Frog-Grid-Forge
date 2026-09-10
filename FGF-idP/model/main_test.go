package model

import (
	"FGF-idP/common"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestEnsureActiveJWKUsesMatchingActiveKey(t *testing.T) {
	db := setupJWKTestDB(t)
	key := generateTestRSAKey(t)
	wantN := common.RsaToBase64urlInt(key.PublicKey.N)
	wantE := common.RsaToBase64urlUint(key.PublicKey.E)

	if err := db.Create(newJWKKey(common.InitialKeyKID, wantN, wantE, "matching key")).Error; err != nil {
		t.Fatalf("create matching key: %v", err)
	}
	common.ActiveKeyID = ""

	if err := ensureActiveJWK(&key.PublicKey); err != nil {
		t.Fatalf("ensure active jwk: %v", err)
	}
	if common.ActiveKeyID != common.InitialKeyKID {
		t.Fatalf("expected existing matching kid %q, got %q", common.InitialKeyKID, common.ActiveKeyID)
	}
}

func TestEnsureActiveJWKCreatesMatchingKeyWhenActiveDiffers(t *testing.T) {
	db := setupJWKTestDB(t)
	oldKey := generateTestRSAKey(t)
	newKey := generateTestRSAKey(t)
	oldN := common.RsaToBase64urlInt(oldKey.PublicKey.N)
	oldE := common.RsaToBase64urlUint(oldKey.PublicKey.E)
	wantN := common.RsaToBase64urlInt(newKey.PublicKey.N)
	wantE := common.RsaToBase64urlUint(newKey.PublicKey.E)

	if err := db.Create(newJWKKey(common.InitialKeyKID, oldN, oldE, "old active key")).Error; err != nil {
		t.Fatalf("create old active key: %v", err)
	}
	common.ActiveKeyID = ""

	if err := ensureActiveJWK(&newKey.PublicKey); err != nil {
		t.Fatalf("ensure active jwk: %v", err)
	}
	if common.ActiveKeyID == "" || common.ActiveKeyID == common.InitialKeyKID {
		t.Fatalf("expected a new matching kid, got %q", common.ActiveKeyID)
	}

	var active JwkKey
	if err := db.Where("kid = ?", common.ActiveKeyID).First(&active).Error; err != nil {
		t.Fatalf("load active key: %v", err)
	}
	if !active.IsActive || active.N != wantN || active.E != wantE {
		t.Fatalf("expected active key to match loaded public key, got active=%t n=%q e=%q", active.IsActive, active.N, active.E)
	}
}

func setupJWKTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	if err := db.AutoMigrate(&JwkKey{}); err != nil {
		t.Fatalf("migrate test db: %v", err)
	}
	previousDB := DB
	previousActiveKeyID := common.ActiveKeyID
	DB = db
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
		DB = previousDB
		common.ActiveKeyID = previousActiveKeyID
	})
	return db
}

func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	return key
}
