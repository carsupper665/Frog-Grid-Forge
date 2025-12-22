package common

// ./common/logger.go

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/bytedance/gopkg/util/gopool"
	"github.com/gin-gonic/gin"
)

const (
	loggerINFO  = ColorBrightCyan + "[INFO]" + ColorReset
	loggerWarn  = ColorYellow + "[WARN]" + ColorReset
	loggerError = ColorRed + "[ERR]" + ColorReset
)

type NoColorWriter struct {
	console io.Writer
	file    io.Writer
	strip   *regexp.Regexp
}

// Write implements io.Writer.
func (w *NoColorWriter) Write(p []byte) (n int, err error) {
	// 無修改寫到 console
	if _, err = w.console.Write(p); err != nil {
		return len(p), err
	}
	// 去掉 ANSI code，再寫到 file
	clean := w.strip.ReplaceAll(p, []byte(""))
	if _, err = w.file.Write(clean); err != nil {
		return len(p), err
	}

	return len(p), nil
}

const maxLogCount = 1000000

var logCount int
var setupLogLock sync.Mutex // 專門拿來鎖的
var setupLogWorking bool

func SplitWriter(console, file io.Writer) io.Writer {
	return &NoColorWriter{
		console: console,
		file:    file,
		// 這個正則會匹配所有 ANSI Escape Code
		strip: regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`),
	}
}

func SetupLogger() {
	if *LogDir != "" {
		// 鎖一下，避免多個同時
		ok := setupLogLock.TryLock()
		if !ok {
			log.Println("setup log is already working")
			return
		}
		defer func() {
			setupLogLock.Unlock()
			setupLogWorking = false
		}()
		logPath := filepath.Join(*LogDir, fmt.Sprintf("server-log-%s.log", time.Now().Format("20060102150405")))
		fd, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal("failed to open log file")
		}

		// 改一下 gin 輸出的地方 -> standard output and standard error
		gin.DefaultWriter = SplitWriter(os.Stdout, fd) // 這裡的 SplitWriter 會把 ANSI code 去掉，寫到檔案
		gin.DefaultErrorWriter = SplitWriter(os.Stderr, fd)
	}
}

func SysLog(s string) {
	t := time.Now()
	_, _ = fmt.Fprintf(gin.DefaultWriter, "\033[32m[SYS]\033[0m %v | %s \n", t.Format("2006/01/02 - 15:04:05"), s)
}

func SysError(s string) {
	t := time.Now()
	_, _ = fmt.Fprintf(gin.DefaultErrorWriter, "\033[31m[SYS] %v | %s \n\033[0m", t.Format("2006/01/02 - 15:04:05"), s)
}

func SysDebug(s string) {
	if !DebugMode {
		return
	}
	t := time.Now()
	_, _ = fmt.Fprintf(gin.DefaultWriter, ColorBrightBlue+"[SYS-DEBUG]%s %v | %s \n", ColorReset, t.Format("2006/01/02 - 15:04:05"), s)
}

func LogInfo(ctx context.Context, msg string) {
	logHelper(ctx, loggerINFO, msg)
}

func LogDebug(ctx context.Context, msg string) {
	if !DebugMode {
		return
	}
	logHelper(ctx, ColorBrightBlue+"[DEBUG]"+ColorReset, msg)
}

func LogWarn(ctx context.Context, msg string) {
	logHelper(ctx, loggerWarn, msg)
}

func LogError(ctx context.Context, msg string) {
	logHelper(ctx, loggerError, msg)
}

func logHelper(ctx context.Context, level string, msg string) {
	writer := gin.DefaultErrorWriter
	if level == loggerINFO {
		writer = gin.DefaultWriter
	}
	id := ctx.Value(RequestIdKey)
	now := time.Now()
	_, _ = fmt.Fprintf(writer, "%s %v | %s | %s \n", level, now.Format("2006/01/02-15:04:05"), msg, id)
	logCount++ // we don't need accurate count, so no lock here
	// 原作不放鎖應該可以節省很多速度?

	// 行數超過就換檔，用SetupLogger
	if logCount > maxLogCount && !setupLogWorking {
		logCount = 0
		setupLogWorking = true
		gopool.Go(func() {
			SetupLogger()
		})
	}
}

func FatalLog(v ...any) {
	t := time.Now()
	_, _ = fmt.Fprintf(gin.DefaultErrorWriter, "[FATAL] %v | %v \n", t.Format("2006/01/02-15:04:05"), v)
	os.Exit(1)
}
