// model/user.go

package model

import (
	"FGF-idP/common"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
)

type User struct {
	ID                 uint           `gorm:"primaryKey;autoIncrement" json:"id"`
	Username           string         `gorm:"size:12;not null;uniqueIndex" json:"username"`
	DisplayName        string         `json:"display_name" gorm:"index" validate:"max=20"`
	Role               int            `gorm:"default:1;not null" json:"role"`
	Email              string         `gorm:"size:255;uniqueIndex;not null" json:"email"`
	Password           string         `gorm:"size:255;not null" json:"-"`
	Salt               string         `gorm:"size:255;not null" json:"-"`
	VerificationCode   string         `gorm:"size:6" json:"verification_code"`
	VerificationSentAt time.Time      `gorm:"autoCreateTime" json:"verification_sent_at"`
	AccessToken        *string        `json:"access_token" gorm:"type:char(32);column:access_token;uniqueIndex"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
	DeletedAt          gorm.DeletedAt `gorm:"index" json:"-"`
}

type UserDevice struct {
	ID         string    `gorm:"primaryKey;size:32" json:"id"`
	UserID     uint      `gorm:"index;not null"   json:"user_id"`
	UserAgent  string    `gorm:"type:text;not null" json:"user_agent"`
	IP         string    `gorm:"size:45;not null"  json:"ip"`
	LastSeenAt time.Time `gorm:"autoUpdateTime"   json:"last_seen_at"`
	CreatedAt  time.Time `gorm:"autoCreateTime"   json:"created_at"`
}

var (
	ErrCodeAlreadySet = errors.New("verification code already set and not expired")
	CodeValidity      = 5 * time.Minute
)

func RootUserExists() bool {
	var user User
	err := DB.Where("role = ?", common.RoleRootUser).First(&user).Error
	return err == nil // 判斷試
}

func LoginByName(username string) (User, error) {

	var user User
	err := DB.
		Where("username = ?", username).
		First(&user).
		Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return User{}, err
		}
		return User{}, err
	}
	return user, nil
}

func LoginByEmail(email string) (User, error) {

	var user User
	err := DB.
		Where("email = ?", email).
		First(&user).
		Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return User{}, err
		}
		return User{}, err
	}
	return user, nil
}

func IsDeviceExists(deviceID string) (bool, error) {
	var count int64
	err := DB.Model(&UserDevice{}).
		Where("id = ?", deviceID).
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

func SetVerificationCode(userID uint, code string) error {
	// 1) 先把現有的 code + sentAt 撈出
	var u User
	if err := DB.Select("verification_code", "verification_sent_at").
		First(&u, userID).Error; err != nil {
		return err
	}

	// 2) 如果已有 code 而且還沒過期，就拒絕
	if u.VerificationCode != "" && time.Since(u.VerificationSentAt) < CodeValidity {
		return ErrCodeAlreadySet
	}

	// 3) 否則寫入新的 code 與時間
	now := time.Now()
	return DB.
		Model(&User{}).
		Where("id = ?", userID).
		Updates(map[string]interface{}{
			"verification_code":    code,
			"verification_sent_at": now,
		}).
		Error
}

// GetVerificationCode retrieves both the code and the time it was sent.
func GetVerificationCode(userEmail string) (code string, sentAt time.Time, err error) {
	var user User
	err = DB.
		Select("verification_code", "verification_sent_at").
		Where("email = ?", userEmail).
		First(&user).
		Error
	if err != nil {
		return "", time.Time{}, err
	}
	return user.VerificationCode, user.VerificationSentAt, nil
}

// ClearVerificationCode resets both the code and its sent timestamp.
func ClearVerificationCode(userEmail string) error {
	return DB.
		Model(&User{}).
		Where("email = ?", userEmail).
		Updates(map[string]interface{}{
			"verification_code":    "",
			"verification_sent_at": time.Time{}, // zero value
		}).
		Error
}

func GetUserByEmail(email string) (User, error) {
	var user User
	err := DB.
		Where("email = ?", email).
		First(&user).
		Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return User{}, err
		}
		return User{}, err
	}
	return user, nil
}

func GetUserByName(username string) (User, error) {
	var user User
	err := DB.
		Where("username = ?", username).
		First(&user).
		Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return User{}, err
		}
		return User{}, err
	}
	return user, nil
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

func GetRole(userID uint) (int, error) {
	var role int
	err := DB.Model(&User{}).Select("role").Where("id = ?", userID).Take(&role).Error
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
