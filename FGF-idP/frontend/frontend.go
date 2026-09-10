package frontend

import (
	"embed"
	"net/http"
	"path"
	"strings"
)

//go:embed index.html admin.html assets/*
var files embed.FS

// ServeHTTP exposes only the embedded login page, the admin console, and the
// asset directory they share. Anything else is a 404, and a traversal attempt
// such as assets/../admin.html fails embed.FS path validation on the way in.
func ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var name string
	switch {
	case r.URL.Path == "/login":
		name = "index.html"
	case r.URL.Path == "/admin":
		name = "admin.html"
	case strings.HasPrefix(r.URL.Path, "/login/assets/"):
		name = strings.TrimPrefix(r.URL.Path, "/login/")
	case strings.HasPrefix(r.URL.Path, "/admin/assets/"):
		name = strings.TrimPrefix(r.URL.Path, "/admin/")
	default:
		http.NotFound(w, r)
		return
	}
	data, err := files.ReadFile(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Type", map[string]string{
		".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
		".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml",
		".webp": "image/webp", ".woff2": "font/woff2",
	}[path.Ext(name)])
	if path.Ext(name) == ".html" {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=3600")
	}
	if r.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
}
