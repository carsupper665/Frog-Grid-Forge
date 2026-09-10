// router/admin.go
package router

import (
	"FGF-idP/common"
	"FGF-idP/controller"
	"FGF-idP/frontend"
	"FGF-idP/middleware"

	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
)

func AdminRouter(router *gin.Engine) {
	// The console shell carries no data and stays open, so a plain browser GET
	// renders a sign-in form instead of a bare JSON 401. Registering it
	// explicitly also keeps NoRoute from redirecting it to FRONTEND_BASE_URL.
	router.GET("/admin", gin.WrapF(frontend.ServeHTTP))
	router.HEAD("/admin", gin.WrapF(frontend.ServeHTTP))
	router.GET("/admin/assets/*path", gin.WrapF(frontend.ServeHTTP))
	router.HEAD("/admin/assets/*path", gin.WrapF(frontend.ServeHTTP))

	// middleware.CORS() is deliberately absent: it sets
	// Access-Control-Allow-Credentials for every configured origin, which would
	// let a listed origin drive this API with an operator session cookie.
	base := []gin.HandlerFunc{
		gzip.Gzip(gzip.DefaultCompression),
		middleware.IpRateLimiter(common.GlobalApiRateLimitNum, common.GlobalApiRateLimitDuration),
	}

	// Sign-in has to sit outside the role gate.
	open := router.Group("/x/admin", base...)
	open.POST("/login", controller.AdminLogin)

	api := router.Group("/x/admin", base...)
	api.Use(middleware.RequireRole(common.RoleAdminUser))
	api.GET("/me", controller.AdminMe)
	api.GET("/users", controller.AdminListUsers)
	api.POST("/users", controller.AdminCreateUser)
	api.GET("/users/:id", controller.AdminGetUser)
	api.PATCH("/users/:id", controller.AdminUpdateUserProfile)
	api.PATCH("/users/:id/role", controller.AdminUpdateUserRole)
	api.DELETE("/users/:id", controller.AdminDeleteUser)

	// Service management sits one level higher: a redirect URI is enough to
	// harvest authorization codes. gin copies group middleware into each route
	// chain, so these routes run [gzip, limiter, RequireRole(4), RequireRole(6)]
	// and the second gate reuses the first lookup.
	clients := api.Group("/clients")
	clients.Use(middleware.RequireRole(common.RoleRootUser))
	clients.GET("", controller.AdminListClients)
	clients.POST("", controller.AdminCreateClient)
	clients.GET("/:client_id", controller.AdminGetClient)
	clients.PATCH("/:client_id", controller.AdminUpdateClient)
	clients.POST("/:client_id/secret", controller.AdminRotateClientSecret)
	clients.DELETE("/:client_id", controller.AdminDeleteClient)
}
