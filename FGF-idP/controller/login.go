package controller

import (
	"FGF-idP/common"
	"FGF-idP/model"
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type loginReq struct {
	Email    string `json:"email" binding:"omitempty,email"`
	Username string `json:"username" binding:"omitempty"`
	Password string `json:"password" binding:"required"`
	ReqID    string `json:"req_id" binding:"required"`
}

func Login(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	var req loginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	if (req.Email == "" && req.Username == "") || (req.Email != "" && req.Username != "") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	authReq, err := model.GetAuthRequest(c.Request.Context(), req.ReqID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_req_id"})
		return
	}
	if err != nil {
		common.LogError(c.Request.Context(), "Read auth request: "+err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	user, err := findLoginUser(req.Email, req.Username)
	if err != nil {
		common.LogError(c.Request.Context(), "Login user lookup error: "+err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials"})
		return
	}
	if !common.ValidatePasswordAndHash(req.Password+user.Salt, user.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials"})
		return
	}
	if err := issueSessionCookie(c, user); err != nil {
		common.LogError(c.Request.Context(), "issue session cookie error: "+err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	deviceID, err := c.Cookie(common.DeviceCookieName)
	if errors.Is(err, http.ErrNoCookie) {
		deviceID = common.GetRandomString(32)
		setCookie(c, common.DeviceCookieName, deviceID, common.DeviceCookieExpireSeconds)
		respondDeviceVerification(c, user, authReq, deviceID, "new_device_detected, verify code sent to email")
		return
	}
	if err != nil {
		common.LogError(c.Request.Context(), "Device cookie error: "+err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "cookie_error"})
		return
	}

	isTrusted, err := model.IsTrustedDevice(user.ID, deviceID)
	if err != nil {
		common.LogError(c.Request.Context(), fmt.Sprintf("Device trust check error: %v", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	if !isTrusted {
		respondDeviceVerification(c, user, authReq, deviceID, "device_verification_required, verify code sent to email")
		return
	}
	issueCodeAndRedirect(c, authReq, user.ID)
}

// findLoginUser resolves a credential by whichever identifier was supplied.
// Shared with the admin console sign-in so both paths look users up alike.
func findLoginUser(email, username string) (model.User, error) {
	if email != "" {
		return model.GetUserByEmail(email)
	}
	return model.GetUserByName(username)
}

func respondDeviceVerification(c *gin.Context, user model.User, authReq *model.AuthRequest, deviceID, message string) {
	if err := CreateVerificationToken(c, user, authReq.ID, deviceID); err != nil {
		common.LogError(c.Request.Context(), "CreateVerificationToken error: "+err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	c.JSON(http.StatusNonAuthoritativeInfo, gin.H{"message": message, "email": user.Email})
}
