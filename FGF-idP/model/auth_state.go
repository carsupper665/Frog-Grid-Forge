package model

import (
	"FGF-idP/common"
	"context"
	"time"

	"gorm.io/gorm"
)

const AuthRequestTTL = 10 * time.Minute
const AuthCodeTTL = 5 * time.Minute

type AuthRequest struct {
	ID                  string `gorm:"primaryKey;size:255"`
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	EmailVerifyToken    *string `gorm:"index"`
	EmailVerifyDeviceID *string
	EmailVerifyUserID   *uint     `gorm:"index"`
	ExpiresAt           time.Time `gorm:"not null;index"`
}

type AuthCode struct {
	Code                string `gorm:"primaryKey;size:255"`
	ClientID            string
	UserID              uint
	RedirectURI         string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time `gorm:"not null;index"`
	IsUsed              bool      `gorm:"not null"`
}

func CreateAuthRequest(ctx context.Context, req *AuthRequest) error {
	req.ExpiresAt = time.Now().Add(AuthRequestTTL)
	return DB.WithContext(ctx).Create(req).Error
}

func GetAuthRequest(ctx context.Context, id string) (*AuthRequest, error) {
	var req AuthRequest
	if err := DB.WithContext(ctx).Where("id = ? AND expires_at > ?", id, time.Now()).First(&req).Error; err != nil {
		return nil, err
	}
	return &req, nil
}

func GetAuthRequestByVerificationToken(ctx context.Context, token string) (*AuthRequest, error) {
	var req AuthRequest
	if err := DB.WithContext(ctx).Where("email_verify_token = ? AND expires_at > ?", token, time.Now()).First(&req).Error; err != nil {
		return nil, err
	}
	return &req, nil
}

func BindAuthVerification(ctx context.Context, id, token, deviceID string, userID uint) error {
	result := DB.WithContext(ctx).Model(&AuthRequest{}).
		Where("id = ? AND expires_at > ?", id, time.Now()).
		Updates(map[string]any{"email_verify_token": token, "email_verify_device_id": deviceID, "email_verify_user_id": userID})
	return requireOneRow(result)
}

// ConsumeAuthVerification claims a live binding before any authentication side effects.
// Matching the token also keeps a failed email send from clearing a newer binding.
func ConsumeAuthVerification(ctx context.Context, id, token, deviceID string) error {
	result := DB.WithContext(ctx).Model(&AuthRequest{}).
		Where("id = ? AND email_verify_token = ? AND email_verify_device_id = ? AND expires_at > ?", id, token, deviceID, time.Now()).
		Updates(map[string]any{"email_verify_token": nil, "email_verify_device_id": nil, "email_verify_user_id": nil})
	return requireOneRow(result)
}

// IssueAuthCode replaces a live request with a code in one transaction. Concurrent
// completions cannot issue multiple codes, and a failed insert preserves the request.
func IssueAuthCode(ctx context.Context, requestID string, code *AuthCode) error {
	return DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Where("id = ? AND expires_at > ?", requestID, time.Now()).Delete(&AuthRequest{})
		if err := requireOneRow(result); err != nil {
			return err
		}
		code.ExpiresAt = time.Now().Add(AuthCodeTTL)
		code.IsUsed = false
		return tx.Create(code).Error
	})
}

func GetAuthCode(ctx context.Context, value string) (*AuthCode, error) {
	var code AuthCode
	if err := DB.WithContext(ctx).Where("code = ? AND expires_at > ?", value, time.Now()).First(&code).Error; err != nil {
		return nil, err
	}
	return &code, nil
}

// ConsumeAuthCode is called only after the controller validates PKCE. The update
// rechecks the validated binding, expiration and single-use condition in the DB.
func ConsumeAuthCode(ctx context.Context, code *AuthCode) error {
	result := DB.WithContext(ctx).Model(&AuthCode{}).
		Where("code = ? AND client_id = ? AND redirect_uri = ? AND code_challenge = ? AND code_challenge_method = ? AND expires_at > ? AND is_used = ?",
			code.Code, code.ClientID, code.RedirectURI, code.CodeChallenge, code.CodeChallengeMethod, time.Now(), false).
		Update("is_used", true)
	if err := requireOneRow(result); err != nil {
		return err
	}
	code.IsUsed = true
	return nil
}

// CleanupExpiredAuthState removes expired requests, codes and token revocations.
func CleanupExpiredAuthState(ctx context.Context) error {
	now := time.Now()
	return DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, record := range []any{&AuthRequest{}, &AuthCode{}, &RevokedToken{}} {
			if err := tx.Where("expires_at <= ?", now).Delete(record).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// requireOneRow preserves storage errors and rejects stale or already consumed state.
func requireOneRow(result *gorm.DB) error {
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// RunAuthCleanup owns the lifetime of expiring authentication records.
func RunAuthCleanup(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		if err := CleanupExpiredAuthState(ctx); err != nil && ctx.Err() == nil {
			common.SysError("auth state cleanup: " + err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
