package router

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestAdminRoutes wires the real router. Every case aborts before reaching the
// database, so no fixture is needed.
func TestAdminRoutes(t *testing.T) {
	t.Setenv("FRONTEND_BASE_URL", "")
	t.Setenv("CORS_ALLOWED_ORIGINS", "")
	r := gin.New()
	SetRouter(r)

	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{http.MethodGet, "/admin", 200},
		{http.MethodGet, "/admin/assets/admin.js", 200},
		{http.MethodGet, "/admin/assets/admin.css", 200},
		// Guarded endpoints must answer 401, not a 404 and not a redirect to
		// FRONTEND_BASE_URL: that would mean NoRoute swallowed them.
		{http.MethodGet, "/x/admin/me", 401},
		{http.MethodGet, "/x/admin/users", 401},
		{http.MethodGet, "/x/admin/clients", 401},
		{http.MethodDelete, "/x/admin/users/1", 401},
		{http.MethodPost, "/x/admin/users", 401},
		{http.MethodGet, "/x/admin/users/1", 401},
		{http.MethodPatch, "/x/admin/users/1", 401},
		// Password reset is a separate capability, not part of profile CRUD.
		{http.MethodPost, "/x/admin/users/1/password", 404},
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.status {
			t.Fatalf("%s %s: expected %d, got %d", tc.method, tc.path, tc.status, w.Code)
		}
		if tc.path == "/admin" && !strings.Contains(w.Body.String(), "Grid Forge") {
			t.Fatal("not serving the embedded admin console")
		}
	}
}

// TestAdminAPIHasNoCORS keeps the admin API off the credentialed CORS surface:
// an allowlisted origin must not be able to drive it with an operator cookie.
func TestAdminAPIHasNoCORS(t *testing.T) {
	t.Setenv("FRONTEND_BASE_URL", "")
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://portal.example")
	r := gin.New()
	SetRouter(r)

	request := httptest.NewRequest(http.MethodGet, "/x/admin/users", nil)
	request.Header.Set("Origin", "https://portal.example")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, request)

	if w.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("admin API advertises credentialed CORS: %v", w.Header())
	}
}
