package main

import (
	"FGF-idP/common"
	"FGF-idP/controller"
	"FGF-idP/model"
	"FGF-idP/router"
	"fmt"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		fmt.Println("Error loading .env file")
	}
	common.LoadEnv()
	common.SetupLogger()
	common.SysLog(fmt.Sprintf("%s, Version: %s%s, Initializing...", common.SystemName, common.Version, common.Build))

	if os.Getenv("DEBUG") != "true" { // gin 預設為 debug 所以要記得關
		common.SysLog(common.ColorGreen + "Running in Release Mode" + common.ColorReset)
		gin.SetMode(gin.ReleaseMode)
	} else {
		common.SysLog(common.ColorBrightCyan + "Debug mode is enabled, running in Debug Mode" + common.ColorReset)
	}

	if err := model.InitDB(); err != nil {
		common.FatalLog("failed to init DB: " + err.Error())
	}

	server := gin.New()
	// CustomRecovery 這邊的作用是超大 exception 機制 如果API哪裡繃了可以防程序崩 再以json回傳問題
	server.Use(gin.CustomRecovery(func(c *gin.Context, err any) {
		common.SysError(fmt.Sprintf("panic detected: %v", err))
		err = common.SendErrorToDc(fmt.Sprintf("Panic detected: %v", err))
		if err != nil {
			common.SysError(fmt.Sprintf("Failed to send error to Discord: %v", err))
		}
		c.JSON(500, gin.H{
			"error": gin.H{
				"message": fmt.Sprintf("Unknow Error: %v", err),
				"type":    "unknow_panic",
			},
		})
	}))
	server.Use(gin.Recovery())
	router.SetRouter(server)
	// init session store
	// store := cookie.NewStore([]byte(common.SessionSecret))
	// store.Options(sessions.Options{
	//	Path:     "/",
	//	MaxAge:   2592000, // 30 days
	//	HttpOnly: true,
	//	Secure:   false,
	//	SameSite: http.SameSiteStrictMode,
	//  })
	// server.Use(sessions.Sessions("session", store))
	controller.InitAuthCache()

	port := common.Port

	common.SysLog(fmt.Sprintf("Listening on port %d", port))
	if err := server.Run(fmt.Sprintf(":%d", port)); err != nil {
		common.FatalLog("failed to start server: " + err.Error())
	}

}
