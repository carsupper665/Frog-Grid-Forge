package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestTrustedProxies(t *testing.T) {
	for _, test := range []struct{ name, proxies, peer, want string }{
		{"none", "", "192.0.2.10:8000", "192.0.2.10"},
		{"untrusted peer", "10.0.0.0/24", "192.0.2.10:8000", "192.0.2.10"},
		{"trusted peer", " 10.0.0.0/24 , ::1 ", "10.0.0.2:8000", "198.51.100.20"},
		{"trusted ipv6", "::1", "[::1]:8000", "198.51.100.20"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("TRUSTED_PROXIES", test.proxies)
			server := gin.New()
			if err := configureTrustedProxies(server); err != nil {
				t.Fatal(err)
			}
			server.GET("/", func(c *gin.Context) { c.String(200, c.ClientIP()) })
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.RemoteAddr = test.peer
			request.Header.Set("X-Forwarded-For", "198.51.100.20")
			request.Header.Set("X-Real-IP", "203.0.113.99")
			response := httptest.NewRecorder()
			server.ServeHTTP(response, request)
			if response.Body.String() != test.want {
				t.Fatalf("client IP = %q, want %q", response.Body.String(), test.want)
			}
		})
	}
	for _, value := range []string{"*", "proxy.example", "10.0.0.0/99", "127.0.0.1,"} {
		t.Setenv("TRUSTED_PROXIES", value)
		if err := configureTrustedProxies(gin.New()); err == nil {
			t.Fatalf("accepted invalid proxy %q", value)
		}
	}
}

func TestHTTPTimeouts(t *testing.T) {
	server := newHTTPServer(":3000", http.NotFoundHandler())
	if server.ReadHeaderTimeout != 5*time.Second || server.ReadTimeout != 15*time.Second || server.WriteTimeout != 30*time.Second || server.IdleTimeout != 60*time.Second {
		t.Fatalf("unexpected HTTP timeout policy: %+v", server)
	}
}

func TestServeHTTPDrainsActiveRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	server := newHTTPServer("127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_, _ = io.WriteString(w, "finished")
	}))
	defer server.Close()
	address := make(chan string, 1)
	server.BaseContext = func(listener net.Listener) context.Context {
		address <- listener.Addr().String()
		return context.Background()
	}
	stopped := make(chan error, 1)
	go func() { stopped <- serveHTTP(ctx, server) }()
	var url string
	select {
	case addr := <-address:
		url = "http://" + addr
	case <-time.After(3 * time.Second):
		t.Fatal("server did not start")
	}
	response := make(chan string, 1)
	go func() {
		client := &http.Client{Timeout: 3 * time.Second}
		result, err := client.Get(url)
		if err != nil {
			response <- err.Error()
			return
		}
		defer result.Body.Close()
		body, _ := io.ReadAll(result.Body)
		response <- string(body)
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not enter handler")
	}
	cancel()
	select {
	case err := <-stopped:
		t.Fatalf("shutdown abandoned active request: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	release <- struct{}{}
	select {
	case body := <-response:
		if body != "finished" {
			t.Fatalf("response = %q", body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("request did not complete")
	}
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown did not finish")
	}
}

func TestServeHTTPReturnsListenError(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := serveHTTP(ctx, newHTTPServer(listener.Addr().String(), http.NotFoundHandler())); err == nil {
		t.Fatal("listen failure was ignored")
	}
}
