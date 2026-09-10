// router/main.go
package router

import (
	"FGF-idP/common"
	"FGF-idP/frontend"
	"FGF-idP/middleware"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func SetRouter(router *gin.Engine) {

	router.Use(middleware.RequestId())

	frontendBaseUrl := common.GetEnvOrDefaultString("FRONTEND_BASE_URL", "")

	frontendBaseUrl = strings.TrimSuffix(frontendBaseUrl, "/")
	router.GET("/login", gin.WrapF(frontend.ServeHTTP))
	router.HEAD("/login", gin.WrapF(frontend.ServeHTTP))
	router.GET("/login/assets/*path", gin.WrapF(frontend.ServeHTTP))
	router.HEAD("/login/assets/*path", gin.WrapF(frontend.ServeHTTP))
	router.NoRoute(func(c *gin.Context) {
		if frontendBaseUrl == "" {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		c.Redirect(http.StatusMovedPermanently, fmt.Sprintf("%s%s", frontendBaseUrl, c.Request.RequestURI))
	})

	AuthRouter(router)
	AdminRouter(router)

}
