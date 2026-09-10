package router

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestProductionLoginRoutes(t *testing.T) {
	t.Setenv("FRONTEND_BASE_URL", "")
	t.Setenv("CORS_ALLOWED_ORIGINS", "")
	r := gin.New()
	SetRouter(r)
	for _, tc := range []struct {
		path   string
		status int
	}{
		{"/login", 200}, {"/login/assets/login.js", 200}, {"/login/assets/", 404},
		{"/cookie/did", 404}, {"/test/start", 404}, {"/server.js", 404}, {"/missing", 404},
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", tc.path, nil))
		if w.Code != tc.status {
			t.Fatalf("%s: %d", tc.path, w.Code)
		}
		if tc.path == "/login" && !strings.Contains(w.Body.String(), "Grid Forge") {
			t.Fatal("not serving embedded UI")
		}
	}
}
