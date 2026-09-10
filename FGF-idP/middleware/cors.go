package middleware

import (
	"FGF-idP/common"
	"fmt"
	"net/url"
	"strings"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func CORS() gin.HandlerFunc {
	config := cors.DefaultConfig()
	config.AllowCredentials = true
	config.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type", "Authorization", "FGF-Request-Id"}
	// An empty allowlist permits only same-origin and non-browser requests.
	config.AllowOriginFunc = func(string) bool { return false }
	raw := strings.TrimSpace(common.GetEnvOrDefaultString("CORS_ALLOWED_ORIGINS", ""))
	if raw != "" {
		for _, value := range strings.Split(raw, ",") {
			origin := strings.TrimSpace(value)
			parsed, err := url.Parse(origin)
			if err != nil || strings.Contains(origin, "*") || parsed.Hostname() == "" ||
				(parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.User != nil ||
				parsed.Path != "" || parsed.RawQuery != "" || parsed.ForceQuery || strings.Contains(origin, "#") {
				panic(fmt.Sprintf("CORS_ALLOWED_ORIGINS: invalid origin %q; use exact http(s) origins without paths or wildcards", origin))
			}
			config.AllowOrigins = append(config.AllowOrigins, origin)
		}
	}
	return cors.New(config)
}
