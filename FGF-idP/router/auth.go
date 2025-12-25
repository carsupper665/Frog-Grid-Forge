package router

import (
	"FGF-idP/common"
	"FGF-idP/controller"
	"FGF-idP/middleware"

	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
)

func AuthRouter(router *gin.Engine) {
	wk := router.Group("/.well-known")
	wk.Use(gzip.Gzip(gzip.DefaultCompression),
		middleware.CORS(),
		middleware.IpRateLimiter(common.GlobalApiRateLimitNum, common.GlobalApiRateLimitDuration),
	)
	wk.GET("/openid-configuration/", controller.JwksMetadata)
	wk.GET("/keys", controller.JwksKeys) // JWKS public keys
	//wk.GET("/keys/:sid", controller.GetKeysBySid)

	rootRouter := router.Group("/x")
	rootRouter.Use(gzip.Gzip(gzip.DefaultCompression),
		middleware.CORS(),
		middleware.IpRateLimiter(common.GlobalApiRateLimitNum, common.GlobalApiRateLimitDuration),
	)

	rootRouter.GET("/auth", controller.Auth)

	rootRouter.POST("/login", controller.Login)
	rootRouter.GET("/verify", controller.EmailVerify)
	rootRouter.POST("/logout")

	rootRouter.POST("/token", controller.Token)
	rootRouter.GET("/userinfo")
	rootRouter.POST("/revoke")
}
