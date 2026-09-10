package controller

import (
	"FGF-idP/common"
	"FGF-idP/middleware"
	"FGF-idP/model"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const jsonContentType = "application/json"

// registerAdminRoutes mirrors router.AdminRouter without the gzip and rate
// limiting layers, which are irrelevant to authorization behaviour.
func registerAdminRoutes(env *controllerTestEnv) {
	env.router.POST("/x/admin/login", AdminLogin)

	api := env.router.Group("/x/admin")
	api.Use(middleware.RequireRole(common.RoleAdminUser))
	api.GET("/me", AdminMe)
	api.GET("/users", AdminListUsers)
	api.POST("/users", AdminCreateUser)
	api.GET("/users/:id", AdminGetUser)
	api.PATCH("/users/:id", AdminUpdateUserProfile)
	api.PATCH("/users/:id/role", AdminUpdateUserRole)
	api.DELETE("/users/:id", AdminDeleteUser)

	clients := api.Group("/clients")
	clients.Use(middleware.RequireRole(common.RoleRootUser))
	clients.GET("", AdminListClients)
	clients.POST("", AdminCreateClient)
	clients.GET("/:client_id", AdminGetClient)
	clients.PATCH("/:client_id", AdminUpdateClient)
	clients.POST("/:client_id/secret", AdminRotateClientSecret)
	clients.DELETE("/:client_id", AdminDeleteClient)
}

func setupAdminTest(t *testing.T) *controllerTestEnv {
	t.Helper()
	env := setupControllerTest(t)
	registerAdminRoutes(env)
	return env
}

// createUser adds a user directly through the model. Username is size:12, so
// callers must keep names short.
func createUser(t *testing.T, name, password string, role int) model.User {
	t.Helper()
	if err := model.AddUser(name, name+"@example.com", name, password, role); err != nil {
		t.Fatalf("add user %q: %v", name, err)
	}
	user, err := model.GetUserByName(name)
	if err != nil {
		t.Fatalf("load user %q: %v", name, err)
	}
	return user
}

func cookieFor(t *testing.T, user model.User) *http.Cookie {
	t.Helper()
	token, err := common.GenerateSessionToken(user.ID, user.Username)
	if err != nil {
		t.Fatalf("generate session token: %v", err)
	}
	return &http.Cookie{Name: common.JwtCookieName, Value: token}
}

func adminRequest(t *testing.T, env *controllerTestEnv, method, target, body string, user model.User) *httptest.ResponseRecorder {
	t.Helper()
	return performRequest(t, env.router, method, target, body, jsonContentType, []*http.Cookie{cookieFor(t, user)})
}

// TestAdminLoginFailuresAreIndistinguishable is the account enumeration guard:
// a wrong password, an unknown account and an under-privileged account must be
// impossible to tell apart, or an attacker could map out the administrators.
func TestAdminLoginFailuresAreIndistinguishable(t *testing.T) {
	env := setupAdminTest(t)
	createUser(t, "plain1", "plain-password-1", common.RoleCommonUser)

	bodies := map[string]string{
		"wrong password":  fmt.Sprintf(`{"account":%q,"password":"not-the-password"}`, env.username),
		"unknown account": `{"account":"nobody-here","password":"not-the-password"}`,
		"role too low":    `{"account":"plain1","password":"plain-password-1"}`,
	}
	var status int
	var payload string
	for name, body := range bodies {
		resp := performRequest(t, env.router, http.MethodPost, "/x/admin/login", body, jsonContentType, nil)
		if hasSetCookie(resp, common.JwtCookieName) {
			t.Fatalf("%s: a failed sign-in must not set a session cookie", name)
		}
		if status == 0 {
			status, payload = resp.Code, resp.Body.String()
			continue
		}
		if resp.Code != status || resp.Body.String() != payload {
			t.Fatalf("%s: response differs from another failure mode: got %d %s, want %d %s",
				name, resp.Code, resp.Body.String(), status, payload)
		}
	}
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", status)
	}
}

func TestAdminLoginSucceedsForRoot(t *testing.T) {
	env := setupAdminTest(t)
	body := fmt.Sprintf(`{"account":%q,"password":%q}`, env.username, env.password)
	resp := performRequest(t, env.router, http.MethodPost, "/x/admin/login", body, jsonContentType, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	if !hasSetCookie(resp, common.JwtCookieName) {
		t.Fatal("expected a session cookie")
	}
	if role, _ := decodeJSONMap(t, resp)["role"].(float64); int(role) != common.RoleRootUser {
		t.Fatalf("expected root role in body, got %s", resp.Body.String())
	}
}

func TestAdminLoginRejectsNonJSON(t *testing.T) {
	env := setupAdminTest(t)
	resp := performRequest(t, env.router, http.MethodPost, "/x/admin/login", "account=x&password=y",
		"application/x-www-form-urlencoded", nil)
	if resp.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415, got %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestAdminRoutesRejectAnonymous(t *testing.T) {
	env := setupAdminTest(t)
	for _, target := range []string{"/x/admin/me", "/x/admin/users", "/x/admin/clients"} {
		resp := performRequest(t, env.router, http.MethodGet, target, "", "", nil)
		if resp.Code != http.StatusUnauthorized {
			t.Fatalf("%s: expected 401, got %d body=%s", target, resp.Code, resp.Body.String())
		}
	}
}

func TestAdminRoutesRejectCommonUser(t *testing.T) {
	env := setupAdminTest(t)
	plain := createUser(t, "plain2", "plain-password-2", common.RoleCommonUser)
	resp := adminRequest(t, env, http.MethodGet, "/x/admin/users", "", plain)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", resp.Code, resp.Body.String())
	}
}

// TestAdminClientsRequireRoot pins the second threshold: managing services is
// strictly above managing users.
func TestAdminClientsRequireRoot(t *testing.T) {
	env := setupAdminTest(t)
	admin := createUser(t, "admin1", "admin-password-1", common.RoleAdminUser)

	if resp := adminRequest(t, env, http.MethodGet, "/x/admin/users", "", admin); resp.Code != http.StatusOK {
		t.Fatalf("admin should reach the user directory, got %d body=%s", resp.Code, resp.Body.String())
	}
	if resp := adminRequest(t, env, http.MethodGet, "/x/admin/clients", "", admin); resp.Code != http.StatusForbidden {
		t.Fatalf("admin must not reach the client directory, got %d body=%s", resp.Code, resp.Body.String())
	}
	if resp := adminRequest(t, env, http.MethodGet, "/x/admin/clients", "", env.user); resp.Code != http.StatusOK {
		t.Fatalf("root should reach the client directory, got %d body=%s", resp.Code, resp.Body.String())
	}
}

// TestAdminListUsersNeverLeaksCredentials guards the DTO and the column
// allowlist together: model.User serializes AccessToken by default.
func TestAdminListUsersNeverLeaksCredentials(t *testing.T) {
	env := setupAdminTest(t)
	createUser(t, "plain3", "plain-password-3", common.RoleCommonUser)

	resp := adminRequest(t, env, http.MethodGet, "/x/admin/users", "", env.user)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	for _, forbidden := range []string{"access_token", "password", "salt", "secret"} {
		if strings.Contains(resp.Body.String(), forbidden) {
			t.Fatalf("response leaks %q: %s", forbidden, resp.Body.String())
		}
	}
}

func TestAdminListUsersPagesAndSearches(t *testing.T) {
	env := setupAdminTest(t)
	createUser(t, "alpha1", "alpha-password-1", common.RoleCommonUser)
	createUser(t, "beta01", "beta-password-01", common.RoleCommonUser)

	resp := adminRequest(t, env, http.MethodGet, "/x/admin/users?size=1", "", env.user)
	body := decodeJSONMap(t, resp)
	if rows, _ := body["users"].([]any); len(rows) != 1 {
		t.Fatalf("expected a single row, got %s", resp.Body.String())
	}
	if more, _ := body["has_more"].(bool); !more {
		t.Fatalf("expected has_more with three users and size=1, got %s", resp.Body.String())
	}

	resp = adminRequest(t, env, http.MethodGet, "/x/admin/users?q=alpha", "", env.user)
	if rows, _ := decodeJSONMap(t, resp)["users"].([]any); len(rows) != 1 {
		t.Fatalf("expected one match for alpha, got %s", resp.Body.String())
	}
}

// TestAdminListUsersEscapesLikeWildcards stops a search term from being read as
// a LIKE pattern.
func TestAdminListUsersEscapesLikeWildcards(t *testing.T) {
	env := setupAdminTest(t)
	createUser(t, "gamma1", "gamma-password-1", common.RoleCommonUser)

	for _, term := range []string{"%", "_", "a%a"} {
		// The term must be percent-encoded or c.Query would decode it to "".
		resp := adminRequest(t, env, http.MethodGet, "/x/admin/users?q="+url.QueryEscape(term), "", env.user)
		rows, _ := decodeJSONMap(t, resp)["users"].([]any)
		if len(rows) != 0 {
			t.Fatalf("term %q behaved as a wildcard and matched %d rows: %s", term, len(rows), resp.Body.String())
		}
	}
}

func TestAdminRoleGuards(t *testing.T) {
	env := setupAdminTest(t)
	admin := createUser(t, "admin2", "admin-password-2", common.RoleAdminUser)
	peer := createUser(t, "admin3", "admin-password-3", common.RoleAdminUser)
	plain := createUser(t, "plain4", "plain-password-4", common.RoleCommonUser)

	for _, tc := range []struct {
		name, want string
		actor      model.User
		target     uint
		role       int
	}{
		{name: "self", want: "forbidden_self", actor: admin, target: admin.ID, role: common.RoleCommonUser},
		{name: "root", want: "forbidden_root", actor: admin, target: env.user.ID, role: common.RoleCommonUser},
		{name: "peer", want: "forbidden_peer", actor: admin, target: peer.ID, role: common.RoleCommonUser},
		{name: "grant own level", want: "forbidden_grant", actor: admin, target: plain.ID, role: common.RoleAdminUser},
		{name: "grant above own level", want: "forbidden_grant", actor: admin, target: plain.ID, role: common.RoleRootUser},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := fmt.Sprintf("/x/admin/users/%d/role", tc.target)
			resp := adminRequest(t, env, http.MethodPatch, target, fmt.Sprintf(`{"role":%d}`, tc.role), tc.actor)
			if resp.Code != http.StatusForbidden {
				t.Fatalf("expected 403, got %d body=%s", resp.Code, resp.Body.String())
			}
			assertJSONError(t, resp, tc.want)
		})
	}

	// Nobody may delete a root account either, not even another root.
	resp := adminRequest(t, env, http.MethodDelete, fmt.Sprintf("/x/admin/users/%d", env.user.ID), "", admin)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403 deleting root, got %d body=%s", resp.Code, resp.Body.String())
	}
}

// TestAdminAssignsGuestRole is the pointer-binding regression: with a plain int
// field the gin required binding would reject RoleGuestUser as missing.
func TestAdminAssignsGuestRole(t *testing.T) {
	env := setupAdminTest(t)
	plain := createUser(t, "plain5", "plain-password-5", common.RoleCommonUser)

	resp := adminRequest(t, env, http.MethodPatch,
		fmt.Sprintf("/x/admin/users/%d/role", plain.ID), `{"role":0}`, env.user)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	role, err := model.GetRole(context.Background(), plain.ID)
	if err != nil || role != common.RoleGuestUser {
		t.Fatalf("stored role = %d, err = %v", role, err)
	}
}

func TestAdminUpdateRoleRejectsBadInput(t *testing.T) {
	env := setupAdminTest(t)
	plain := createUser(t, "plain6", "plain-password-6", common.RoleCommonUser)
	path := fmt.Sprintf("/x/admin/users/%d/role", plain.ID)

	for _, tc := range []struct {
		name, target, body, contentType, wantErr string
		status                                   int
	}{
		{name: "unknown role 3", target: path, body: `{"role":3}`, contentType: jsonContentType, status: http.StatusBadRequest, wantErr: "invalid_role"},
		{name: "unknown role 99", target: path, body: `{"role":99}`, contentType: jsonContentType, status: http.StatusBadRequest, wantErr: "invalid_role"},
		{name: "missing role", target: path, body: `{}`, contentType: jsonContentType, status: http.StatusBadRequest, wantErr: "invalid_request"},
		{name: "non numeric id", target: "/x/admin/users/abc/role", body: `{"role":1}`, contentType: jsonContentType, status: http.StatusBadRequest, wantErr: "invalid_request"},
		{name: "unknown id", target: "/x/admin/users/999999/role", body: `{"role":1}`, contentType: jsonContentType, status: http.StatusNotFound, wantErr: "not_found"},
		{name: "form content type", target: path, body: "role=1", contentType: "text/plain", status: http.StatusUnsupportedMediaType, wantErr: "unsupported_media_type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := performRequest(t, env.router, http.MethodPatch, tc.target, tc.body, tc.contentType,
				[]*http.Cookie{cookieFor(t, env.user)})
			if resp.Code != tc.status {
				t.Fatalf("expected %d, got %d body=%s", tc.status, resp.Code, resp.Body.String())
			}
			assertJSONError(t, resp, tc.wantErr)
		})
	}
}

// TestAdminDeleteUserRevokesAccess proves the middleware reads the live row:
// a soft deleted account loses its session on the very next request.
func TestAdminDeleteUserRevokesAccess(t *testing.T) {
	env := setupAdminTest(t)
	admin := createUser(t, "admin4", "admin-password-4", common.RoleAdminUser)

	if resp := adminRequest(t, env, http.MethodGet, "/x/admin/me", "", admin); resp.Code != http.StatusOK {
		t.Fatalf("expected the admin session to work, got %d body=%s", resp.Code, resp.Body.String())
	}
	resp := adminRequest(t, env, http.MethodDelete, fmt.Sprintf("/x/admin/users/%d", admin.ID), "", env.user)
	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d body=%s", resp.Code, resp.Body.String())
	}
	if resp := adminRequest(t, env, http.MethodGet, "/x/admin/me", "", admin); resp.Code != http.StatusUnauthorized {
		t.Fatalf("deleted user still authenticated: %d body=%s", resp.Code, resp.Body.String())
	}
	if _, err := model.GetUserByName("admin4"); err == nil {
		t.Fatal("deleted user is still resolvable by name")
	}
	if listed := adminRequest(t, env, http.MethodGet, "/x/admin/users", "", env.user); strings.Contains(listed.Body.String(), "admin4") {
		t.Fatalf("deleted user still appears in the directory: %s", listed.Body.String())
	}
}

// TestAdminRoleChangeTakesEffectImmediately is the counterpart to caching the
// role anywhere: a demotion must bite on the next request even though the
// session cookie is unchanged.
func TestAdminRoleChangeTakesEffectImmediately(t *testing.T) {
	env := setupAdminTest(t)
	admin := createUser(t, "admin5", "admin-password-5", common.RoleAdminUser)
	cookie := cookieFor(t, admin)

	resp := performRequest(t, env.router, http.MethodGet, "/x/admin/me", "", "", []*http.Cookie{cookie})
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200 before demotion, got %d", resp.Code)
	}
	if err := model.UpdateUserRole(context.Background(), admin.ID, common.RoleCommonUser); err != nil {
		t.Fatalf("demote: %v", err)
	}
	resp = performRequest(t, env.router, http.MethodGet, "/x/admin/me", "", "", []*http.Cookie{cookie})
	if resp.Code != http.StatusForbidden {
		t.Fatalf("demoted admin kept access with the same cookie: %d body=%s", resp.Code, resp.Body.String())
	}
}
