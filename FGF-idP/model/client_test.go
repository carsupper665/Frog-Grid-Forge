package model

import (
	"context"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func setupClientTestDB(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	previous := DB
	DB = db
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
		DB = previous
	})
}

// TestClientMigrationKeepsExistingClientsWorking is the upgrade path check.
// Adding Name, the timestamps and DeletedAt to Client rewrites the table on an
// existing deployment; a mistake there would take every registered service
// offline on the first restart after the upgrade.
func TestClientMigrationKeepsExistingClientsWorking(t *testing.T) {
	setupClientTestDB(t)

	// The clients table exactly as it existed before the admin console.
	if err := DB.Exec(`CREATE TABLE clients (
		client_id TEXT PRIMARY KEY,
		secret_hash TEXT NOT NULL,
		redirect_uris JSON,
		scope TEXT,
		grant_types JSON,
		response_types JSON
	)`).Error; err != nil {
		t.Fatalf("create legacy table: %v", err)
	}
	if err := DB.Exec(`INSERT INTO clients VALUES (?, ?, ?, ?, ?, ?)`,
		"legacy-client", "hash", `["https://app.example.com/cb"]`,
		"openid profile", `["authorization_code"]`, `["code"]`).Error; err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}

	if err := DB.AutoMigrate(&Client{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	ok, msg, err := ValiClientWithUrl("legacy-client", "https://app.example.com/cb")
	if err != nil {
		t.Fatalf("validate legacy client: %v", err)
	}
	if !ok {
		t.Fatalf("a client registered before the upgrade stopped working: %s", msg)
	}
	if exists, err := ClientExists("legacy-client"); err != nil || !exists {
		t.Fatalf("legacy client invisible to the token endpoint: exists=%v err=%v", exists, err)
	}
}

// TestListClientsOmitsSecretHash pins the column allowlist at the storage layer,
// so a future DTO change cannot start leaking the hash.
func TestListClientsOmitsSecretHash(t *testing.T) {
	setupClientTestDB(t)
	if err := DB.AutoMigrate(&Client{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := CreateClient(context.Background(), &Client{
		ClientID: "svc", Name: "Service", SecretHash: "super-secret-hash", Scope: "openid",
	}); err != nil {
		t.Fatalf("create client: %v", err)
	}

	listed, _, err := ListClients(context.Background(), "", 1, 10)
	if err != nil {
		t.Fatalf("list clients: %v", err)
	}
	if len(listed) != 1 || listed[0].SecretHash != "" {
		t.Fatalf("ListClients returned a secret hash: %+v", listed)
	}
	fetched, err := GetClient(context.Background(), "svc")
	if err != nil || fetched.SecretHash != "" {
		t.Fatalf("GetClient returned a secret hash: %+v err=%v", fetched, err)
	}

	if err := CreateClient(context.Background(), &Client{ClientID: "svc"}); err != ErrClientExists {
		t.Fatalf("expected ErrClientExists, got %v", err)
	}
}
