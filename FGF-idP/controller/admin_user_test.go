package controller

import (
	"FGF-idP/common"
	"FGF-idP/model"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAdminUserCRUD(t *testing.T) {
	env := setupAdminTest(t)
	body := `{"username":"New.User","display_name":"新使用者","email":"New@Example.com","password":"initial-password-123","role":0}`
	created := adminRequest(t, env, "POST", "/x/admin/users", body, env.user)
	if created.Code != 201 {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	for _, secret := range []string{"password", "salt", "access_token", "initial-password"} {
		if strings.Contains(created.Body.String(), secret) {
			t.Fatal("credential leaked", secret)
		}
	}
	var view userView
	if err := json.Unmarshal(created.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	user, err := model.GetUserByID(view.ID)
	if err != nil {
		t.Fatal(err)
	}
	if user.Username != "new.user" || user.Email != "new@example.com" || user.Role != 0 || !common.ValidatePasswordAndHash("initial-password-123"+user.Salt, user.Password) {
		t.Fatal("creation did not preserve identity, guest role or password")
	}
	path := fmt.Sprintf("/x/admin/users/%d", user.ID)
	read := adminRequest(t, env, "GET", path, "", env.user)
	if read.Code != 200 || strings.Contains(read.Body.String(), "password") {
		t.Fatalf("read: %d %s", read.Code, read.Body.String())
	}
	updated := adminRequest(t, env, "PATCH", path, `{"username":"renamed","display_name":"更新名稱","email":"updated@example.com","role":6,"password":"ignored-secret"}`, env.user)
	if updated.Code != 200 {
		t.Fatalf("update: %d %s", updated.Code, updated.Body.String())
	}
	saved, _ := model.GetUserByID(user.ID)
	if saved.Username != "renamed" || saved.DisplayName != "更新名稱" || saved.Email != "updated@example.com" || saved.Role != 0 || saved.Password != user.Password {
		t.Fatal("profile update changed unrelated fields")
	}
	cleared := adminRequest(t, env, "PATCH", path, `{"display_name":""}`, env.user)
	if cleared.Code != 200 {
		t.Fatalf("clear name: %d %s", cleared.Code, cleared.Body.String())
	}
	deleted := adminRequest(t, env, "DELETE", path, "", env.user)
	if deleted.Code != 204 {
		t.Fatal("delete failed")
	}
	if adminRequest(t, env, "GET", path, "", env.user).Code != 404 {
		t.Fatal("deleted user still readable")
	}
	if adminRequest(t, env, "GET", "/x/admin/me", "", saved).Code != 401 {
		t.Fatal("deleted user's session still accepted")
	}
}

func TestAdminUserCreateValidationAndConflicts(t *testing.T) {
	env := setupAdminTest(t)
	valid := map[string]any{"username": "created", "display_name": "New", "email": "created@example.com", "password": "long-password-123"}
	for _, tc := range []struct {
		key    string
		value  any
		status int
	}{
		{"username", "bad name", 400}, {"username", strings.Repeat("a", 13), 400}, {"email", "Name <a@example.com>", 400},
		{"email", "invalid", 400}, {"display_name", strings.Repeat("字", 21), 400}, {"password", "short", 400},
		{"password", strings.Repeat("a", 57), 400}, {"role", 2, 400}, {"role", 6, 403},
	} {
		input := map[string]any{}
		for key, value := range valid {
			input[key] = value
		}
		input[tc.key] = tc.value
		raw, _ := json.Marshal(input)
		result := adminRequest(t, env, "POST", "/x/admin/users", string(raw), env.user)
		if result.Code != tc.status {
			t.Fatalf("%s: %d %s", tc.key, result.Code, result.Body.String())
		}
	}
	existing := createUser(t, "existing", "existing-password", 1)
	for _, pair := range []struct{ username, email string }{{"EXISTING", "other@example.com"}, {"other", "EXISTING@EXAMPLE.COM"}} {
		valid["username"], valid["email"] = pair.username, pair.email
		raw, _ := json.Marshal(valid)
		result := adminRequest(t, env, "POST", "/x/admin/users", string(raw), env.user)
		if result.Code != 409 {
			t.Fatalf("duplicate: %d %s", result.Code, result.Body.String())
		}
	}
	if err := model.DeleteUser(context.Background(), existing.ID); err != nil {
		t.Fatal(err)
	}
	valid["username"], valid["email"] = "existing", "existing@example.com"
	raw, _ := json.Marshal(valid)
	if adminRequest(t, env, "POST", "/x/admin/users", string(raw), env.user).Code != 409 {
		t.Fatal("reused deleted identity")
	}
}

func TestAdminUserCRUDPermissions(t *testing.T) {
	env := setupAdminTest(t)
	admin := createUser(t, "editor", "long-password-123", 4)
	peer := createUser(t, "peer", "long-password-123", 4)
	plain := createUser(t, "ordinary", "long-password-123", 1)
	for _, target := range []model.User{admin, peer, env.user} {
		result := adminRequest(t, env, "PATCH", fmt.Sprintf("/x/admin/users/%d", target.ID), `{"display_name":"blocked"}`, admin)
		if result.Code != 403 {
			t.Fatalf("target %s: %d", target.Username, result.Code)
		}
	}
	if adminRequest(t, env, "POST", "/x/admin/users", `{"username":"blocked","email":"blocked@example.com","password":"initial-password-123","role":4}`, admin).Code != 403 {
		t.Fatal("admin created peer")
	}
	for _, method := range []string{"GET", "POST", "PATCH"} {
		path := "/x/admin/users"
		if method != "POST" {
			path += fmt.Sprintf("/%d", plain.ID)
		}
		anonymous := performRequest(t, env.router, method, path, `{}`, jsonContentType, nil)
		if anonymous.Code != 401 {
			t.Fatal("anonymous access", method, anonymous.Code)
		}
		if adminRequest(t, env, method, path, `{}`, plain).Code != 403 {
			t.Fatal("ordinary user accessed management")
		}
	}
	for _, method := range []string{"POST", "PATCH"} {
		path := "/x/admin/users"
		if method == "PATCH" {
			path += fmt.Sprintf("/%d", plain.ID)
		}
		result := performRequest(t, env.router, method, path, `{}`, "text/plain", []*http.Cookie{cookieFor(t, env.user)})
		if result.Code != 415 {
			t.Fatal("non-JSON mutation accepted", method, result.Code)
		}
	}
}

func TestAdminUserEmailChangeInvalidatesTrust(t *testing.T) {
	env := setupAdminTest(t)
	user := createUser(t, "emailowner", "long-password-123", 1)
	ctx := context.Background()
	if err := model.SaveDevice("email-device", "browser", "127.0.0.1", user.ID); err != nil {
		t.Fatal(err)
	}
	token, err := common.GenEmailSignedToken(user.Email)
	if err != nil {
		t.Fatal(err)
	}
	req := &model.AuthRequest{ID: "email-change", ClientID: env.clientID, RedirectURI: env.redirectURI, Scope: "openid"}
	if err := model.CreateAuthRequest(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := model.BindAuthVerification(ctx, req.ID, token, "email-device", user.ID); err != nil {
		t.Fatal(err)
	}
	if err := model.DB.Create(&model.AuthCode{Code: "pending-code", UserID: user.ID, ExpiresAt: time.Now().Add(time.Minute)}).Error; err != nil {
		t.Fatal(err)
	}
	result := adminRequest(t, env, "PATCH", fmt.Sprintf("/x/admin/users/%d", user.ID), `{"email":"changed@example.com"}`, env.user)
	if result.Code != 200 {
		t.Fatalf("email update: %d %s", result.Code, result.Body.String())
	}
	if trusted, _ := model.IsTrustedDevice(user.ID, "email-device"); trusted {
		t.Fatal("old device trusted")
	}
	if _, err := model.GetAuthCode(ctx, "pending-code"); err == nil {
		t.Fatal("old code usable")
	}
	if _, err := model.GetAuthRequest(ctx, req.ID); err == nil {
		t.Fatal("old binding retained")
	}
	// Even if a stale binding were restored, immutable user ID must reject email reuse.
	other := createUser(t, "newowner", "long-password-123", 1)
	if err := model.DB.Model(&model.User{}).Where("id = ?", other.ID).Update("email", user.Email).Error; err != nil {
		t.Fatal(err)
	}
	if err := model.CreateAuthRequest(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := model.BindAuthVerification(ctx, req.ID, token, "email-device", user.ID); err != nil {
		t.Fatal(err)
	}
	verify := performRequest(t, env.router, "GET", "/x/verify?t="+url.QueryEscape(token), "", "", []*http.Cookie{{Name: common.DeviceCookieName, Value: "email-device"}})
	if verify.Code != 400 || hasSetCookie(verify, common.JwtCookieName) {
		t.Fatalf("old link authenticated reassigned email: %d", verify.Code)
	}
}

func TestAdminUserEditConflictLeavesDataUnchanged(t *testing.T) {
	env := setupAdminTest(t)
	first := createUser(t, "first", "long-password-123", 1)
	second := createUser(t, "second", "long-password-123", 1)
	result := adminRequest(t, env, "PATCH", fmt.Sprintf("/x/admin/users/%d", first.ID), `{"display_name":"must not save","email":"second@example.com"}`, env.user)
	if result.Code != 409 {
		t.Fatalf("conflict: %d %s", result.Code, result.Body.String())
	}
	saved, _ := model.GetUserByID(first.ID)
	if saved.DisplayName != first.DisplayName || saved.Email != first.Email {
		t.Fatal("partial update on conflict")
	}
	previous := second
	if err := model.UpdateUserRole(context.Background(), second.ID, 6); err != nil {
		t.Fatal(err)
	}
	second.DisplayName = "stale edit"
	if err := model.UpdateManagedUser(context.Background(), previous, second); err == nil {
		t.Fatal("stale edit of promoted root accepted")
	}
}
