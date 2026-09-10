package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestCORSOrigins(t *testing.T) {
	for _, test := range []struct {
		name, allowlist, origin, method string
		status                          int
		credentials                     bool
	}{
		{"non-browser", "", "", "GET", 200, false},
		{"same-origin", "", "http://idp.example", "GET", 200, false},
		{"default denies cross-origin", "", "https://portal.example", "GET", 403, false},
		{"default denies preflight", "", "https://portal.example", "OPTIONS", 403, false},
		{"allowed", " https://other.example , https://portal.example ", "https://portal.example", "GET", 200, true},
		{"allowed preflight", "https://portal.example", "https://portal.example", "OPTIONS", 204, true},
		{"unlisted", "https://portal.example", "https://evil.example", "GET", 403, false},
		{"suffix attack", "https://portal.example", "https://portal.example.evil", "GET", 403, false},
		{"different port", "https://portal.example", "https://portal.example:8443", "GET", 403, false},
		{"null origin", "https://portal.example", "null", "GET", 403, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("CORS_ALLOWED_ORIGINS", test.allowlist)
			server := gin.New()
			server.Use(CORS())
			called := false
			server.GET("/", func(c *gin.Context) { called = true; c.Status(http.StatusOK) })
			request := httptest.NewRequest(test.method, "http://idp.example/", nil)
			request.Header.Set("Origin", test.origin)
			if test.method == "OPTIONS" {
				request.Header.Set("Access-Control-Request-Method", "POST")
				request.Header.Set("Access-Control-Request-Headers", "authorization,content-type")
			}
			response := httptest.NewRecorder()
			server.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
			if called != (test.status == 200) {
				t.Fatalf("handler called = %v", called)
			}
			if test.credentials {
				if response.Header().Get("Access-Control-Allow-Origin") != test.origin || response.Header().Get("Access-Control-Allow-Credentials") != "true" {
					t.Fatalf("missing exact credentialed CORS headers: %v", response.Header())
				}
				if !strings.Contains(strings.Join(response.Header().Values("Vary"), ","), "Origin") {
					t.Fatal("missing Vary: Origin")
				}
				if test.method == "OPTIONS" && !strings.Contains(response.Header().Get("Access-Control-Allow-Headers"), "Authorization") {
					t.Fatal("authorization header not permitted")
				}
			} else if response.Header().Get("Access-Control-Allow-Origin") != "" || response.Header().Get("Access-Control-Allow-Credentials") != "" {
				t.Fatalf("unexpected CORS permission: %v", response.Header())
			}
		})
	}
}

func TestCORSRejectsInvalidConfiguration(t *testing.T) {
	for _, value := range []string{"*", "https://*.example.com", "https://ok.example,*", "null", "example.com", "ftp://example.com", "https://user@example.com", "https://example.com/", "https://example.com?q=x", "https://example.com?", "https://example.com#", "https://example.com/#x", "https://example.com,", ",", "https://"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("CORS_ALLOWED_ORIGINS", value)
			defer func() {
				if recover() == nil {
					t.Fatal("invalid configuration must fail startup")
				}
			}()
			CORS()
		})
	}
}
