package model

import (
	"FGF-idP/common"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"gorm.io/gorm/clause"
)

var (
	ErrTokenRevoked   = errors.New("token revoked")
	ErrInvalidSession = errors.New("invalid session claims")
)

type RevokedToken struct {
	Hash      string    `gorm:"primaryKey;size:64"`
	ExpiresAt time.Time `gorm:"index;not null"`
}

func tokenHash(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// ValidateToken is the authentication boundary: signature, claims, then revocation.
func ValidateToken(ctx context.Context, token string) (map[string]interface{}, error) {
	claims, err := common.GetJWTPayload(token)
	if err != nil {
		return nil, err
	}
	if DB == nil {
		return nil, errors.New("token store unavailable")
	}
	var count int64
	err = DB.WithContext(ctx).Model(&RevokedToken{}).Where("hash = ? AND expires_at > ?", tokenHash(token), time.Now()).Count(&count).Error
	if err != nil {
		return nil, err
	}
	if count != 0 {
		return nil, ErrTokenRevoked
	}
	return claims, nil
}

func RevokeToken(ctx context.Context, token string, expiresAt time.Time) error {
	if DB == nil {
		return errors.New("token store unavailable")
	}
	return DB.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&RevokedToken{
		Hash: tokenHash(token), ExpiresAt: expiresAt,
	}).Error
}

// SessionUserID validates a session cookie token and returns its subject.
// It is shared by the controller layer and the role middleware so the claim
// checks live in exactly one place.
func SessionUserID(ctx context.Context, token string) (uint, error) {
	payload, err := ValidateToken(ctx, token)
	if err != nil {
		return 0, err
	}
	username, _ := payload["username"].(string)
	rawUID, _ := payload["user_id"].(string)
	if payload["typ"] != "session" || username == "" || rawUID == "" {
		return 0, ErrInvalidSession
	}
	uid, err := strconv.ParseUint(rawUID, 10, 32)
	if err != nil {
		return 0, ErrInvalidSession
	}
	return uint(uid), nil
}
