package frontend

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEmbeddedLogin(t *testing.T) {
	for _, tc := range []struct {
		path, content string
		status        int
	}{
		{"/login", "text/html", 200}, {"/login?req_id=test", "text/html", 200},
		{"/login/assets/login.js", "javascript", 200}, {"/login/assets/login.css", "text/css", 200},
		{"/login/assets/forest.webp", "image/webp", 200}, {"/login/assets/inter-latin.woff2", "font/woff2", 200},
		{"/login/assets/", "", 404}, {"/login/assets/../index.html", "", 404},
		{"/login/assets/missing.js", "", 404}, {"/frontend.go", "", 404},
		{"/admin", "text/html", 200},
		{"/admin/assets/admin.js", "javascript", 200}, {"/admin/assets/admin.css", "text/css", 200},
		{"/admin/assets/login.css", "text/css", 200}, {"/admin/assets/inter-latin.woff2", "font/woff2", 200},
		{"/admin/assets/", "", 404}, {"/admin/assets/../admin.html", "", 404},
		{"/admin.html", "", 404}, {"/admin/", "", 404},
	} {
		t.Run(tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			ServeHTTP(w, httptest.NewRequest("GET", tc.path, nil))
			if w.Code != tc.status {
				t.Fatalf("status=%d", w.Code)
			}
			if tc.status == 200 && !strings.Contains(w.Header().Get("Content-Type"), tc.content) {
				t.Fatal(w.Header())
			}
			if tc.path == "/admin" {
				assertPageHeaders(t, w)
				// The console CSP forbids inline script and style, so the
				// markup must not rely on either.
				body := w.Body.String()
				for _, banned := range []string{"onclick=", "onchange=", "onsubmit=", "style=\""} {
					if strings.Contains(body, banned) {
						t.Fatalf("admin page uses %q, which the CSP blocks", banned)
					}
				}
			}
			if strings.HasPrefix(tc.path, "/login?") || tc.path == "/login" {
				assertPageHeaders(t, w)
				if !strings.Contains(w.Body.String(), `autocomplete="current-password"`) || strings.Contains(w.Body.String(), "client_secret") {
					t.Fatal("unexpected production form")
				}
			}
		})
	}
	w := httptest.NewRecorder()
	ServeHTTP(w, httptest.NewRequest(http.MethodHead, "/login", nil))
	if w.Code != 200 || w.Body.Len() != 0 {
		t.Fatal("HEAD response has a body")
	}
}

// assertPageHeaders pins the no-store plus strict CSP pair that every embedded
// HTML page must carry.
func assertPageHeaders(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("expected no-store, got %q", w.Header().Get("Cache-Control"))
	}
	policy := w.Header().Get("Content-Security-Policy")
	for _, directive := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(policy, directive) {
			t.Fatalf("missing %q in CSP %q", directive, policy)
		}
	}
}
