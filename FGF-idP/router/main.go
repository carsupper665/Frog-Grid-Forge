// router/main.go
package router

import (
	// "embed"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// buildFS embed.FS, indexPage []byte 暫時不需要 除非日後有需要 搞同源
func SetRouter(router *gin.Engine) {

	frontendBaseUrl := os.Getenv("FRONTEND_BASE_URL")

	frontendBaseUrl = strings.TrimSuffix(frontendBaseUrl, "/")
	router.NoRoute(func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, fmt.Sprintf("%s%s", frontendBaseUrl, c.Request.RequestURI))
	})

	AuthRouter(router)

}
