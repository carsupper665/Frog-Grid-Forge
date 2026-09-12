// controller/admin.go
//
// Admin console sign-in, identity, and the user directory. Shared helpers for
// controller/admin_client.go live here too.

package controller

import (
	"FGF-idP/common"
	"FGF-idP/model"
	"errors"
	"net/http"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// actor is the authenticated caller, taken only from what middleware.RequireRole
// stored. A handler must never read the caller identity from the request.
type actor struct {
	ID   uint
	Role int
}

func currentActor(c *gin.Context) actor {
	id, _ := c.Get(common.CtxUserID)
	role, _ := c.Get(common.CtxRole)
	userID, _ := id.(uint)
	level, _ := role.(int)
	return actor{ID: userID, Role: level}
}

func fail(c *gin.Context, status int, code string) {
	c.JSON(status, gin.H{"error": code})
}

// wantsJSON rejects a body sent under a content type gin would not parse, which
// also blocks the simple cross-site form posts that bypass a CORS preflight.
func wantsJSON(c *gin.Context) bool {
	return strings.HasPrefix(c.ContentType(), "application/json")
}

func pathID(c *gin.Context) (uint, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		return 0, false
	}
	return uint(id), true
}

func pageParams(c *gin.Context) (page, size int) {
	page, _ = strconv.Atoi(c.Query("page"))
	size, _ = strconv.Atoi(c.Query("size"))
	return page, size
}

// userView is the only user shape the admin API returns. model.User must never
// be serialized directly: its AccessToken field carries no json:"-" tag.
type userView struct {
	ID          uint      `json:"id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	Email       string    `json:"email"`
	Role        int       `json:"role"`
	CreatedAt   time.Time `json:"created_at"`
}

func newUserView(user model.User) userView {
	return userView{
		ID: user.ID, Username: user.Username, DisplayName: user.DisplayName,
		Email: user.Email, Role: user.Role, CreatedAt: user.CreatedAt,
	}
}

type adminLoginReq struct {
	Account  string `json:"account" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// AdminLogin is the console sign-in, independent of the OAuth flow so an
// operator never has to register a relying party just to reach the console.
//
// A missing account, a wrong password and an insufficient role all return the
// same response. Distinguishing them would tell an attacker which accounts are
// administrators.
func AdminLogin(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if !wantsJSON(c) {
		fail(c, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	}
	var req adminLoginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, "invalid_request")
		return
	}
	account := strings.TrimSpace(req.Account)
	var email, username string
	if strings.Contains(account, "@") {
		email = account
	} else {
		username = account
	}
	user, err := findLoginUser(email, username)
	if err != nil || !common.ValidatePasswordAndHash(req.Password+user.Salt, user.Password) ||
		user.Role < common.RoleAdminUser {
		fail(c, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	if err := issueSessionCookie(c, user); err != nil {
		common.LogError(c.Request.Context(), "admin login session cookie: "+err.Error())
		fail(c, http.StatusInternalServerError, "server_error")
		return
	}
	// A session alone never opens the console: RequireRole also demands a
	// device this user has verified by email, exactly like the OAuth flow.
	deviceID, err := c.Cookie(common.DeviceCookieName)
	if errors.Is(err, http.ErrNoCookie) {
		deviceID = common.GetRandomString(32)
		setCookie(c, common.DeviceCookieName, deviceID, common.DeviceCookieExpireSeconds)
	}
	trusted, err := model.IsTrustedDevice(user.ID, deviceID)
	if err != nil {
		common.LogError(c.Request.Context(), "admin login device check: "+err.Error())
		fail(c, http.StatusInternalServerError, "server_error")
		return
	}
	if !trusted {
		authReq := &model.AuthRequest{ID: c.Request.Context().Value(common.RequestIdKey).(string), ClientID: common.AdminConsoleClientID}
		if err := model.CreateAuthRequest(c.Request.Context(), authReq); err != nil {
			common.LogError(c.Request.Context(), "admin login verification request: "+err.Error())
			fail(c, http.StatusInternalServerError, "server_error")
			return
		}
		respondDeviceVerification(c, user, authReq, deviceID, "device_verification_required, verify link sent to email")
		return
	}
	common.LogInfo(c.Request.Context(), "admin sign-in: "+user.Username)
	c.JSON(http.StatusOK, gin.H{"id": user.ID, "username": user.Username, "display_name": user.DisplayName, "role": user.Role})
}

// AdminMe tells the console who is signed in so it can hide what the caller
// cannot use. The server remains the authority on every mutation.
func AdminMe(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	a := currentActor(c)
	user, err := model.GetUserByID(a.ID)
	if err != nil {
		common.LogError(c.Request.Context(), "admin me lookup: "+err.Error())
		fail(c, http.StatusInternalServerError, "server_error")
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": user.ID, "username": user.Username, "display_name": user.DisplayName, "role": a.Role})
}

func AdminListUsers(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	page, size := pageParams(c)
	users, hasMore, err := model.ListUsers(c.Request.Context(), c.Query("q"), page, size)
	if err != nil {
		common.LogError(c.Request.Context(), "admin list users: "+err.Error())
		fail(c, http.StatusInternalServerError, "server_error")
		return
	}
	views := make([]userView, 0, len(users))
	for _, user := range users {
		views = append(views, newUserView(user))
	}
	c.JSON(http.StatusOK, gin.H{"users": views, "has_more": hasMore})
}

// guardTarget is the single place the admin API decides whether an actor may
// act on a target user. Every mutating handler calls it before touching
// storage. It returns an empty string when the change is allowed.
func guardTarget(a actor, target model.User) string {
	switch {
	case target.ID == a.ID:
		// No self promotion and no self deletion.
		return "forbidden_self"
	case target.Role >= common.RoleRootUser:
		// Root accounts are provisioned by CREATE_ROOT_USER and are immutable here.
		return "forbidden_root"
	case target.Role >= a.Role:
		return "forbidden_peer"
	}
	return ""
}

// adminRoleReq holds Role as a pointer because the gin required binding treats
// an int zero value as missing, and RoleGuestUser is 0.
type adminRoleReq struct {
	Role *int `json:"role" binding:"required"`
}

func AdminUpdateUserRole(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	a := currentActor(c)
	if !wantsJSON(c) {
		fail(c, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	}
	targetID, ok := pathID(c)
	if !ok {
		fail(c, http.StatusBadRequest, "invalid_request")
		return
	}
	var req adminRoleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, "invalid_request")
		return
	}
	if !common.IsKnownRole(*req.Role) {
		fail(c, http.StatusBadRequest, "invalid_role")
		return
	}
	target, err := loadTarget(c, targetID)
	if err != nil {
		return
	}
	if code := guardTarget(a, target); code != "" {
		fail(c, http.StatusForbidden, code)
		return
	}
	// Separate from guardTarget because this is about the requested value, not
	// the target: nobody may hand out a level at or above their own.
	if *req.Role >= a.Role {
		fail(c, http.StatusForbidden, "forbidden_grant")
		return
	}
	if err := model.UpdateUserRole(c.Request.Context(), target, *req.Role); err != nil {
		adminUserWriteError(c, err)
		return
	}
	common.LogInfo(c.Request.Context(), "admin role change: actor="+
		strconv.FormatUint(uint64(a.ID), 10)+" target="+
		strconv.FormatUint(uint64(targetID), 10)+" role="+strconv.Itoa(*req.Role))
	target.Role = *req.Role
	c.JSON(http.StatusOK, newUserView(target))
}

func AdminDeleteUser(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	a := currentActor(c)
	targetID, ok := pathID(c)
	if !ok {
		fail(c, http.StatusBadRequest, "invalid_request")
		return
	}
	target, err := loadTarget(c, targetID)
	if err != nil {
		return
	}
	if code := guardTarget(a, target); code != "" {
		fail(c, http.StatusForbidden, code)
		return
	}
	if err := model.DeleteUser(c.Request.Context(), target); err != nil {
		adminUserWriteError(c, err)
		return
	}
	common.LogInfo(c.Request.Context(), "admin delete user: actor="+
		strconv.FormatUint(uint64(a.ID), 10)+" target="+
		strconv.FormatUint(uint64(targetID), 10))
	c.Status(http.StatusNoContent)
}

// loadTarget fetches the user a mutation names and writes the failure response
// itself, so callers only have to return.
func loadTarget(c *gin.Context, targetID uint) (model.User, error) {
	target, err := model.GetUserByID(targetID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		fail(c, http.StatusNotFound, "not_found")
		return model.User{}, err
	}
	if err != nil {
		common.LogError(c.Request.Context(), "admin target lookup: "+err.Error())
		fail(c, http.StatusInternalServerError, "server_error")
		return model.User{}, err
	}
	return target, nil
}

var adminUsernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{3,12}$`)

func validUserProfile(username, name, email string) bool {
	address, err := mail.ParseAddress(email)
	return adminUsernamePattern.MatchString(username) && utf8.RuneCountInString(name) <= 20 &&
		len(email) <= 255 && err == nil && address.Address == email && strings.Contains(email, "@")
}

func AdminCreateUser(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if !wantsJSON(c) {
		fail(c, 415, "unsupported_media_type")
		return
	}
	var req struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Email       string `json:"email"`
		Password    string `json:"password"`
		Role        *int   `json:"role"`
	}
	if c.ShouldBindJSON(&req) != nil {
		fail(c, 400, "invalid_request")
		return
	}
	req.Username = strings.ToLower(strings.TrimSpace(req.Username))
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if !validUserProfile(req.Username, req.DisplayName, req.Email) {
		fail(c, 400, "invalid_user_profile")
		return
	}
	// bcrypt allows 72 bytes; the existing password format appends a 16-byte salt.
	if utf8.RuneCountInString(req.Password) < 12 || len(req.Password) > 56 {
		fail(c, 400, "invalid_password")
		return
	}
	role := common.RoleCommonUser
	if req.Role != nil {
		role = *req.Role
	}
	if !common.IsKnownRole(role) {
		fail(c, 400, "invalid_role")
		return
	}
	if role >= currentActor(c).Role {
		fail(c, 403, "forbidden_grant")
		return
	}
	salt := common.GetRandomString(16)
	hash, err := common.Password2Hash(req.Password + salt)
	if err != nil {
		fail(c, 500, "server_error")
		return
	}
	user := model.User{Username: req.Username, DisplayName: req.DisplayName, Email: req.Email, Password: hash, Salt: salt, Role: role}
	if err := model.CreateManagedUser(c.Request.Context(), &user); err != nil {
		adminUserWriteError(c, err)
		return
	}
	common.LogInfo(c.Request.Context(), "admin create user: "+strconv.FormatUint(uint64(user.ID), 10))
	c.JSON(http.StatusCreated, newUserView(user))
}

func AdminGetUser(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	id, ok := pathID(c)
	if !ok {
		fail(c, 400, "invalid_request")
		return
	}
	user, err := loadTarget(c, id)
	if err != nil {
		return
	}
	c.JSON(http.StatusOK, newUserView(user))
}

func AdminUpdateUserProfile(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if !wantsJSON(c) {
		fail(c, 415, "unsupported_media_type")
		return
	}
	id, ok := pathID(c)
	if !ok {
		fail(c, 400, "invalid_request")
		return
	}
	target, err := loadTarget(c, id)
	if err != nil {
		return
	}
	if code := guardTarget(currentActor(c), target); code != "" {
		fail(c, 403, code)
		return
	}
	var req struct {
		Username    *string `json:"username"`
		DisplayName *string `json:"display_name"`
		Email       *string `json:"email"`
	}
	if c.ShouldBindJSON(&req) != nil || (req.Username == nil && req.DisplayName == nil && req.Email == nil) {
		fail(c, 400, "invalid_request")
		return
	}
	updated := target
	if req.Username != nil {
		updated.Username = strings.ToLower(strings.TrimSpace(*req.Username))
	}
	if req.DisplayName != nil {
		updated.DisplayName = strings.TrimSpace(*req.DisplayName)
	}
	if req.Email != nil {
		updated.Email = strings.ToLower(strings.TrimSpace(*req.Email))
	}
	if !validUserProfile(updated.Username, updated.DisplayName, updated.Email) {
		fail(c, 400, "invalid_user_profile")
		return
	}
	if err := model.UpdateManagedUser(c.Request.Context(), target, updated); err != nil {
		adminUserWriteError(c, err)
		return
	}
	common.LogInfo(c.Request.Context(), "admin update user: "+strconv.FormatUint(uint64(id), 10))
	c.JSON(http.StatusOK, newUserView(updated))
}

func adminUserWriteError(c *gin.Context, err error) {
	if errors.Is(err, model.ErrUserIdentityExists) {
		fail(c, 409, "user_exists")
		return
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		fail(c, 409, "user_changed")
		return
	}
	common.LogError(c.Request.Context(), "admin user write failed: "+err.Error())
	fail(c, 500, "server_error")
}
