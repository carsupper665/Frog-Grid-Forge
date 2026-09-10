package router

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// SetHealthRoutes keeps probes independent of authentication and rate limits.
func SetHealthRoutes(server *gin.Engine, ping func(context.Context) error) {
	server.GET("/health/live", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	server.GET("/health/ready", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		if err := ping(ctx); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unavailable"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
}
