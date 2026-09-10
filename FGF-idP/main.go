package main

import (
	"FGF-idP/common"
	"FGF-idP/middleware"
	"FGF-idP/model"
	"FGF-idP/router"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/mattn/go-colorable"
)

func main() {
	defer colorable.EnableColorsStdout(nil)()
	if err := run(); err != nil {
		common.FatalLog(err)
	}
}

func run() error {
	if err := godotenv.Load(); err != nil {
		fmt.Println("Error loading .env file")
	}

	common.LoadEnv()
	common.SetupLogger() // 兼容舊的logger
	common.InitLogger()
	logger := common.Logger
	logger.Debugf("system says, Hi is me, FGF-idP, Version: %s%s, Initializing...", common.Version, common.Build)
	common.SysLog(fmt.Sprintf("%s, Version: %s%s, Initializing...", common.SystemName, common.Version, common.Build))

	if !common.GetEnvOrDefaultBool("DEBUG", false) { // gin 預設為 debug 所以要記得關
		common.SysLog(common.ColorGreen + "Running in Release Mode" + common.ColorReset)
		gin.SetMode(gin.ReleaseMode)
	} else {
		common.SysLog(common.ColorBrightCyan + "Debug mode is enabled, running in Debug Mode" + common.ColorReset)
	}

	if err := model.InitDB(); err != nil {
		return fmt.Errorf("init DB: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	sqlDB, err := model.DB.DB()
	if err != nil {
		return fmt.Errorf("access DB connection pool: %w", err)
	}
	cleanupDone := make(chan struct{})
	go func() {
		defer close(cleanupDone)
		model.RunAuthCleanup(ctx)
	}()
	defer func() {
		stop()
		<-cleanupDone
		_ = sqlDB.Close()
	}()

	server := gin.New()
	if err := configureTrustedProxies(server); err != nil {
		return fmt.Errorf("invalid TRUSTED_PROXIES: %w", err)
	}
	// CustomRecovery 這邊的作用是超大 exception 機制 如果API哪裡繃了可以防程序崩 再以json回傳問題
	server.Use(gin.CustomRecovery(func(c *gin.Context, err any) {
		common.SysError(fmt.Sprintf("panic detected: %v", err))
		dcErr := common.SendErrorToDc(fmt.Sprintf("server name:%s Server Build: %s Panic detected: %v", common.SystemName, common.BuildNocolor, err))
		if dcErr != nil {
			common.SysError(fmt.Sprintf("Failed to send error to Discord: %v", dcErr))
		}
		c.JSON(500, gin.H{
			"error": gin.H{
				"message": fmt.Sprintf("Unknow Error: %v", err),
				"type":    "unknow_panic",
			},
		})
	}))
	middleware.SetUpLogger(server)
	logger.Debug("init middleware complete")
	router.SetRouter(server)
	router.SetHealthRoutes(server, sqlDB.PingContext)
	port := common.Port

	common.SysLog(fmt.Sprintf("Listening on port %d", port))
	return serveHTTP(ctx, newHTTPServer(fmt.Sprintf(":%d", port), server))

}

func configureTrustedProxies(server *gin.Engine) error {
	var proxies []string
	if raw := strings.TrimSpace(common.GetEnvOrDefaultString("TRUSTED_PROXIES", "")); raw != "" {
		for _, value := range strings.Split(raw, ",") {
			proxies = append(proxies, strings.TrimSpace(value))
		}
	}
	return server.SetTrustedProxies(proxies)
}

func newHTTPServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func serveHTTP(ctx context.Context, server *http.Server) error {
	stopped := make(chan error, 1)
	go func() { stopped <- server.ListenAndServe() }()
	select {
	case err := <-stopped:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			return err
		}
		return nil
	}
}
