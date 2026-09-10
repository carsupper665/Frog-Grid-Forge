package controller

import (
	"FGF-idP/common"
	"FGF-idP/frontend"
	"FGF-idP/model"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestLoginPageRedirectSettings(t *testing.T) {
	for _, tc := range []struct{ base, route, want string }{
		{"", "", "/login"}, {"https://portal.example/", "/sign-in", "https://portal.example/sign-in"},
		{"", "https://accounts.example/login", "https://accounts.example/login"},
	} {
		t.Setenv("FRONTEND_BASE_URL", tc.base)
		t.Setenv("FRONTEND_LOGIN_ROUTE", tc.route)
		actual, err := url.Parse(loginRedirectURL("request-id", "device_verification_required"))
		if err != nil {
			t.Fatal(err)
		}
		if actual.Query().Get("req_id") != "request-id" || actual.Query().Get("reason") != "device_verification_required" {
			t.Fatal(actual)
		}
		actual.RawQuery = ""
		if actual.String() != tc.want {
			t.Fatalf("got %s, want %s", actual, tc.want)
		}
	}
}

func TestLoginJSONAndRedirectCompatibility(t *testing.T) {
	env := setupControllerTest(t)
	if err := model.SaveDevice(env.deviceID, "test", "127.0.0.1", env.user.ID); err != nil {
		t.Fatal(err)
	}
	for _, accept := range []string{"application/json", "", "text/html", "*/*"} {
		reqID := startAuthorization(t, env, "login-page")
		body, _ := json.Marshal(map[string]string{"username": env.username, "password": env.password, "req_id": reqID})
		w := performRequestWithHeaders(t, env.router, "POST", "/x/login", string(body), "application/json", []*http.Cookie{{Name: common.DeviceCookieName, Value: env.deviceID}}, map[string]string{"Accept": accept})
		destination := w.Header().Get("Location")
		if accept == "application/json" {
			if w.Code != 200 {
				t.Fatalf("JSON: %d %s", w.Code, w.Body.String())
			}
			var response struct {
				RedirectTo string `json:"redirect_to"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			destination = response.RedirectTo
		} else if w.Code != 302 {
			t.Fatalf("legacy: %d", w.Code)
		}
		parsed, err := url.Parse(destination)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Query().Get("code") == "" || parsed.Query().Get("state") != "login-page" || !strings.HasPrefix(destination, env.redirectURI) {
			t.Fatal(destination)
		}
		if !hasSetCookie(w, common.JwtCookieName) || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("missing session or no-store")
		}
	}
}

func TestVerifyBrowserErrorCompatibility(t *testing.T) {
	env := setupControllerTest(t)
	t.Setenv("FRONTEND_BASE_URL", "")
	for _, tc := range []struct {
		accept string
		status int
	}{
		{"text/html,application/xhtml+xml", 303}, {"application/json", 400}, {"", 400},
	} {
		w := performRequestWithHeaders(t, env.router, "GET", "/x/verify", "", "", nil, map[string]string{"Accept": tc.accept})
		if w.Code != tc.status {
			t.Fatalf("%s: %d", tc.accept, w.Code)
		}
		if tc.status == 303 && w.Header().Get("Location") != "/login?error=missing_token" {
			t.Fatal(w.Header())
		}
		if tc.status == 400 {
			assertJSONError(t, w, "missing_token")
		}
		if w.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Fatal("verification URL may leak")
		}
	}
}

// Opt-in, loopback-only browser fixture; absent from production builds.
func TestLoginBrowserServer(t *testing.T) {
	address := os.Getenv("FGF_BROWSER_TEST_ADDR")
	if address == "" {
		t.Skip("browser fixture not requested")
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil || host != "127.0.0.1" {
		t.Fatal("fixture must bind loopback")
	}
	env := setupControllerTest(t)
	t.Setenv("FRONTEND_BASE_URL", "")
	if err := model.SaveDevice(env.deviceID, "test", "127.0.0.1", env.user.ID); err != nil {
		t.Fatal(err)
	}
	env.router.GET("/login", gin.WrapF(frontend.ServeHTTP))
	env.router.GET("/login/assets/*path", gin.WrapF(frontend.ServeHTTP))
	env.router.GET("/test/start", func(c *gin.Context) { c.Redirect(302, authPath(env, "browser-state", "openid profile")) })
	server := &http.Server{Addr: address, Handler: env.router, ReadHeaderTimeout: 5 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	env.router.POST("/test/stop", func(c *gin.Context) { c.Status(204); cancel() })
	go func() {
		<-ctx.Done()
		shutdown, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = server.Shutdown(shutdown)
	}()
	fmt.Println("LOGIN_BROWSER_READY", address)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		t.Fatal(err)
	}
}
