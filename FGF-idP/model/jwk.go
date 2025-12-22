package model

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type Client struct {
	// 建議用 ID 或 ClientID 做單一主鍵，先挑一個
	ClientID   string `gorm:"primaryKey;column:client_id;size:64"` // OIDC 的 client_id
	SecretHash string `gorm:"column:secret_hash;size:255;not null"`

	// redirect_uris: ["https://a/cb", "https://b/cb"]
	RedirectURIs datatypes.JSON `gorm:"column:redirect_uris;type:json"` // 存 []string 的 JSON

	Scope         string         `gorm:"column:scope;type:text"`       // "openid profile offline_access"
	GrantTypes    datatypes.JSON `gorm:"column:grant_types;type:json"` // []string
	ResponseTypes datatypes.JSON `gorm:"column:response_types;type:json"`
}

type JwkKey struct {
	ID  uint   `gorm:"primaryKey;autoIncrement" json:"id"` // primary key
	Sid string `gorm:"size:64;index;not null" json:"sid"`  // Service ID
	// JWK 內的 kid（字串 Key ID，會寫進 JWT header）
	Kid string `gorm:"size:128;not null;index:idx_service_kid,unique" json:"kid"`
	// JWK 標準欄位
	Kty string `gorm:"size:16;not null" json:"kty"`               // 一般是 "RSA"
	Use string `gorm:"size:16;not null;default:'sig'" json:"use"` // "sig" or "enc"
	Alg string `gorm:"size:32;not null;default:'RS256'" json:"alg"`
	// RSA 公鑰的 modulus / exponent，base64url 編碼的字串
	N string `gorm:"type:text;not null" json:"n"`
	E string `gorm:"type:text;not null" json:"e"`
	// 狀態控制：哪幾把 key 在用、哪幾把停用
	IsActive  bool       `gorm:"index;not null;default:true" json:"is_active"`
	NotBefore *time.Time `json:"not_before"` // 這把 key 從什麼時候開始有效（可為 nil）
	ExpiresAt *time.Time `json:"expires_at"` // 這把 key 什麼時候過期（可為 nil）
	// 方便做 rotate 或 rollback 的備註
	Description string         `gorm:"size:255" json:"description"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

type JakMetadata struct {
	ID uint `gorm:"primaryKey;autoIncrement" json:"id"`
	// 對齊 JwkKey 的 Sid
	Sid string `gorm:"size:64;not null;uniqueIndex" json:"service_id"`
	// 這個 service 對外宣告的 Issuer（通常就是你的 IdP base URL 或某個子路徑）
	Issuer string `gorm:"size:255;not null" json:"issuer"`
	// JWKS 對外的 URL（給 discovery 用）
	JwksURI string `gorm:"size:255;not null" json:"jwks_uri"`
	// 如果這個 service 也扮演 OIDC Provider，可以順便放：
	AuthorizationEndpoint string `gorm:"size:255" json:"authorization_endpoint"`
	TokenEndpoint         string `gorm:"size:255" json:"token_endpoint"`
	UserinfoEndpoint      string `gorm:"size:255" json:"userinfo_endpoint"`
	EndSessionEndpoint    string `gorm:"size:255" json:"end_session_endpoint"`
	// Rotation 策略（例如多少小時 rotate 一次）
	RotateIntervalHours int            `gorm:"not null;default:0" json:"rotate_interval_hours"` // 0 表示不自動 rotate
	LastRotatedAt       *time.Time     `json:"last_rotated_at"`
	NextRotateAt        *time.Time     `json:"next_rotate_at"`
	CreatedAt           time.Time      `json:"created_at"`
	UpdatedAt           time.Time      `json:"updated_at"`
	DeletedAt           gorm.DeletedAt `gorm:"index" json:"-"`
}

func getMetadata() (*JakMetadata, error) {
	var metadata *JakMetadata
	err := DB.Find(&metadata).Error
	return metadata, err
}

func GetDiscovery() (*JakMetadata, error) {
	if jwkMetadata == nil {
		return nil, gorm.ErrRecordNotFound
	}
	return jwkMetadata, nil
}

func GetActiveKeys() ([]JwkKey, error) {
	var keys []JwkKey
	err := DB.Where("is_active = ?", true).Find(&keys).Error
	return keys, err
}

func GetKeyBySid(sid string) ([]JwkKey, error) {
	var keys []JwkKey
	err := DB.
		Where("service_id = ? AND is_active = ?", sid, true).
		Find(&keys).Error
	return keys, err
}

func ValiClientWithUrl(clientID, redirectURI string) (bool, string, error) {
	var client Client
	err := DB.Where("client_id = ?", clientID).First(&client).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, "Client not found", nil
		}
		return false, "Database err: " + err.Error(), err
	}
	var redirectURIs []string
	if len(client.RedirectURIs) > 0 {
		if err := json.Unmarshal(client.RedirectURIs, &redirectURIs); err != nil {
			return false, "Failed to parse redirect URIs", err
		}
	}
	for _, uri := range redirectURIs {
		if strings.HasPrefix(redirectURI, uri) || redirectURI == uri {
			return true, "", nil
		}
	}
	return false, "Redirect URI not registered", nil

}
