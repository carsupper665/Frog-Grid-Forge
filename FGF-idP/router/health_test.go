package router

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestHealthRoutes(t *testing.T) {
	for _, test := range []struct {
		name, path string
		pingErr    error
		status     int
		calls      int
	}{
		{"live independent of database", "/health/live", errors.New("private database error"), 200, 0},
		{"ready", "/health/ready", nil, 200, 1},
		{"unavailable", "/health/ready", errors.New("private database error"), 503, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := gin.New()
			calls := 0
			SetHealthRoutes(server, func(ctx context.Context) error {
				calls++
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 2*time.Second {
					t.Fatal("readiness must bound ping to two seconds")
				}
				return test.pingErr
			})
			response := httptest.NewRecorder()
			server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
			if response.Code != test.status || calls != test.calls {
				t.Fatalf("status %d, ping calls %d", response.Code, calls)
			}
			if strings.Contains(response.Body.String(), "private") {
				t.Fatal("database error leaked")
			}
		})
	}
}

func TestReadinessPreservesRequestCancellation(t *testing.T) {
	server := gin.New()
	SetHealthRoutes(server, func(ctx context.Context) error { return ctx.Err() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	response := httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health/ready", nil).WithContext(ctx))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", response.Code)
	}
}
