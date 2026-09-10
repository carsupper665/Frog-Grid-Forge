// model/user.go

package model

import (
	"FGF-idP/common"
	"context"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
)

type User struct {
	ID          uint           `gorm:"primaryKey;autoIncrement" json:"id"`
	Username    string         `gorm:"size:12;not null;uniqueIndex" json:"username"`
	DisplayName string         `json:"display_name" gorm:"index" validate:"max=20"`
	Role        int            `gorm:"default:1;not null" json:"role"`
	Email       string         `gorm:"size:255;uniqueIndex;not null" json:"email"`
	Password    string         `gorm:"size:255;not null" json:"-"`
	Salt        string         `gorm:"size:255;not null" json:"-"`
	AccessToken *string        `json:"access_token" gorm:"type:char(32);column:access_token;uniqueIndex"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

type UserDevice struct {
	ID         string    `gorm:"primaryKey;size:32" json:"id"`
	UserID     uint      `gorm:"index;not null"   json:"user_id"`
	UserAgent  string    `gorm:"type:text;not null" json:"user_agent"`
	IP         string    `gorm:"size:45;not null"  json:"ip"`
	LastSeenAt time.Time `gorm:"autoUpdateTime"   json:"last_seen_at"`
	CreatedAt  time.Time `gorm:"autoCreateTime"   json:"created_at"`
}

func rootUserExists() (bool, error) {
	var count int64
	err := DB.Model(&User{}).Where("role = ?", common.RoleRootUser).Count(&count).Error
	return count > 0, err
}

func findUser(where string, value any) (User, error) {
	var user User
	err := DB.Where(where, value).First(&user).Error
	if err != nil {
		return User{}, err
	}
	return user, nil
}

func IsTrustedDevice(userID uint, deviceID string) (bool, error) {
	if deviceID == "" {
		return false, nil
	}
	var count int64
	err := DB.Model(&UserDevice{}).
		Where("id = ? AND user_id = ?", deviceID, userID).
		Count(&count).
		Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func SaveDevice(deviceID, userAgent, ip string, userID uint) error {
	device := UserDevice{
		ID:        deviceID,
		UserID:    userID,
		UserAgent: userAgent,
		IP:        ip,
	}
	return DB.Save(&device).Error
}

func DeleteDevice(deviceID string) error {
	return DB.Where("id = ?", deviceID).Delete(&UserDevice{}).Error
}

func GetUserByEmail(email string) (User, error) {
	return findUser("email = ?", email)
}

func GetUserByID(userID uint) (User, error) {
	return findUser("id = ?", userID)
}

func GetUserByName(username string) (User, error) {
	return findUser("username = ?", username)
}

// untested methods
func AddUser(userName, userEmail, displayName, password string, role int) error {
	salt := common.GetRandomString(16)
	h, err := common.Password2Hash(password + salt)
	if err != nil {
		return err
	}
	err = DB.Create(&User{
		Username:    userName,
		Email:       userEmail,
		DisplayName: displayName,
		Password:    h,
		Salt:        salt,
		Role:        role,
	}).Error

	return err
}

var ErrUserNotFound = errors.New("user not found")

// GetRole reads the stored permission level. A soft deleted account has no live
// row, so a stale session cookie stops working on its next request.
func GetRole(ctx context.Context, userID uint) (int, error) {
	var role int
	err := DB.WithContext(ctx).Model(&User{}).Select("role").Where("id = ?", userID).Take(&role).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, ErrUserNotFound
	}
	return role, err
}

func UpdateUser(userID uint, userName, displayName, email string, role int) error {
	updates := map[string]interface{}{}

	if userName != "" {
		updates["username"] = userName
	}

	if displayName != "" {
		updates["display_name"] = displayName
	}

	if role != -1 {
		updates["role"] = role
	}

	if email != "" {
		if _, err := GetUserByEmail(email); err == nil {
			return errors.New("email already in use")
		}

		if strings.Contains(email, "@") {
			updates["email"] = email
		}
	}

	return DB.Model(&User{}).Where("id = ?", userID).Updates(updates).Error
}

func UpdatePassword(userID uint, newPassword string) error {
	salt := common.GetRandomString(16)
	h, err := common.Password2Hash(newPassword + salt)

	if err != nil {
		return err
	}

	return DB.Model(&User{}).Where("id = ?", userID).Updates(map[string]interface{}{
		"password": h,
		"salt":     salt,
	}).Error
}

// userListColumns is an allowlist: Password and Salt are json:"-" but
// AccessToken is not, so the admin directory must never select it.
var userListColumns = []string{"id", "username", "display_name", "email", "role", "created_at"}

// ListUsers returns one page of live users ordered by id, and whether a further
// page exists. LOWER(...) LIKE is used instead of ILIKE so the same statement
// runs on both SQLite and PostgreSQL.
func ListUsers(ctx context.Context, search string, page, size int) ([]User, bool, error) {
	offset, limit, size := pageArgs(page, size)
	query := DB.WithContext(ctx).Model(&User{}).Select(userListColumns)
	if strings.TrimSpace(search) != "" {
		pattern := likePattern(search)
		query = query.Where(
			`LOWER(username) LIKE ? ESCAPE '\' OR LOWER(display_name) LIKE ? ESCAPE '\' OR LOWER(email) LIKE ? ESCAPE '\'`,
			pattern, pattern, pattern)
	}
	var users []User
	if err := query.Order("id").Offset(offset).Limit(limit).Find(&users).Error; err != nil {
		return nil, false, err
	}
	users, hasMore := trimPage(users, size)
	return users, hasMore, nil
}

// UpdateUserRole sets a live user's permission level. Callers must have already
// authorized the change; this performs no privilege checks.
// Update with a single column is required: Updates(struct) would silently skip
// RoleGuestUser because it is the zero value.
func UpdateUserRole(ctx context.Context, userID uint, role int) error {
	return requireOneRow(DB.WithContext(ctx).Model(&User{}).Where("id = ?", userID).Update("role", role))
}

// DeleteUser soft deletes a user. Authorization is the caller's responsibility.
func DeleteUser(ctx context.Context, userID uint) error {
	return requireOneRow(DB.WithContext(ctx).Where("id = ?", userID).Delete(&User{}))
}

var ErrUserIdentityExists = errors.New("username or email already exists")

func checkUserIdentity(tx *gorm.DB, user User) error {
	var count int64
	err := tx.Unscoped().Model(&User{}).Where("id <> ? AND (LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?))", user.ID, user.Username, user.Email).Count(&count).Error
	if err != nil {
		return err
	}
	if count > 0 {
		return ErrUserIdentityExists
	}
	return nil
}

func CreateManagedUser(ctx context.Context, user *User) error {
	role := user.Role
	err := DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := checkUserIdentity(tx, *user); err != nil {
			return err
		}
		if err := tx.Create(user).Error; err != nil {
			return err
		}
		// GORM's default:1 otherwise overwrites an explicitly requested guest.
		if role == 0 {
			user.Role = 0
			return tx.Model(user).Update("role", 0).Error
		}
		return nil
	})
	if err != nil && errors.Is(checkUserIdentity(DB.WithContext(ctx), *user), ErrUserIdentityExists) {
		return ErrUserIdentityExists
	}
	return err
}

func UpdateManagedUser(ctx context.Context, previous, updated User) error {
	err := DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := checkUserIdentity(tx, updated); err != nil {
			return err
		}
		result := tx.Model(&User{}).Where("id = ? AND role = ? AND updated_at = ?", previous.ID, previous.Role, previous.UpdatedAt).Updates(map[string]any{
			"username": updated.Username, "display_name": updated.DisplayName, "email": updated.Email,
		})
		if err := requireOneRow(result); err != nil {
			return err
		}
		if previous.Email == updated.Email {
			return nil
		}
		for _, record := range []any{&UserDevice{}, &AuthCode{}} {
			if err := tx.Where("user_id = ?", previous.ID).Delete(record).Error; err != nil {
				return err
			}
		}
		return tx.Where("email_verify_user_id = ?", previous.ID).Delete(&AuthRequest{}).Error
	})
	if err != nil && errors.Is(checkUserIdentity(DB.WithContext(ctx), updated), ErrUserIdentityExists) {
		return ErrUserIdentityExists
	}
	return err
}
