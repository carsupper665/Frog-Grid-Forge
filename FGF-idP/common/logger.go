// ./common/logger.go
package common

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bytedance/gopkg/util/gopool"
	"github.com/gin-gonic/gin"
	"github.com/mattn/go-colorable"
	"github.com/muesli/termenv"
)

const (
	levelColorDebug   = "6"
	levelColorInfo    = "2"
	levelColorWarn    = "11"
	levelColorError   = "1"
	levelColorDefault = "10"
	levelColorFatal   = "13"
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

//const maxLogCount = 1000000

var setupLogLock sync.Mutex // 專門拿來鎖的

func SplitWriter(console, file io.Writer) io.Writer {
	return &NoColorWriter{
		console: console,
		file:    file,
		// 這個正則會匹配所有 ANSI Escape Code
		strip: regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`),
	}
}

func colorize(text, colorCode string) string {
	profile := termenv.ColorProfile()
	return termenv.String(text).Foreground(profile.Color(colorCode)).String()
}

func levelColor(level int) string {
	switch level {
	case DEBUG:
		return levelColorDebug
	case INFO:
		return levelColorInfo
	case WARNING:
		return levelColorWarn
	case ERROR:
		return levelColorError
	default:
		return levelColorDefault
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
		}()
		logPath := filepath.Join(*LogDir, fmt.Sprintf("server-log-%s.log", time.Now().Format("20060102150405")))
		fd, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal("failed to open log file")
		}

		// 改一下 gin 輸出的地方 -> standard output and standard error
		cstd := colorable.NewColorableStdout()
		cstdErr := colorable.NewColorableStderr()
		gin.DefaultWriter = SplitWriter(cstd, fd) // 這裡的 SplitWriter 會把 ANSI code 去掉，寫到檔案
		gin.DefaultErrorWriter = SplitWriter(cstdErr, fd)
	}
}

func SysLog(s string) {
	Logger.Info(s)
}

func SysError(s string) {
	Logger.Error(s)
}

func SysDebug(s string) {
	Logger.Debug(s)
}

func LogInfo(ctx context.Context, msg string) {
	msg = withRequestID(ctx, msg)
	if Logger == nil {
		log.Println(msg)
		return
	}
	Logger.Info(msg)
}

func LogDebug(ctx context.Context, msg string) {
	if !DebugMode {
		return
	}
	msg = withRequestID(ctx, msg)
	if Logger == nil {
		log.Println(msg)
		return
	}
	Logger.Debug(msg)
}

func LogWarn(ctx context.Context, msg string) {
	msg = withRequestID(ctx, msg)
	if Logger == nil {
		log.Println(msg)
		return
	}
	Logger.Warn(msg)
}

func LogError(ctx context.Context, msg string) {
	msg = withRequestID(ctx, msg)
	if Logger == nil {
		log.Println(msg)
		return
	}
	Logger.Error(msg)
}

func withRequestID(ctx context.Context, msg string) string {
	if ctx == nil {
		return msg
	}
	id, ok := ctx.Value(RequestIdKey).(string)
	if !ok || id == "" {
		return msg
	}
	return fmt.Sprintf("%s | %s", msg, id)
}

func FatalLog(v ...any) {
	t := time.Now()
	_, _ = fmt.Fprintf(gin.DefaultErrorWriter, "[FATAL] %v | %v \n", t.Format("2006/01/02-15:04:05"), v)
	os.Exit(1)
}

var sysLogLock sync.Mutex
var sysLogInitWorking atomic.Bool

func NewSysLogger(logName string, fileName *string, max int) (logger *SysLogger, err error) {
	var LogPath = LogDir
	if *LogPath != "" {
		if ok := sysLogLock.TryLock(); !ok {
			log.Print("setup log is already working")
			return nil, errors.New("setup log is already working")
		}

		sysLogInitWorking.Store(true)

		defer func() {
			sysLogLock.Unlock()
			sysLogInitWorking.Store(false)
		}()
		if err := os.MkdirAll(*LogPath, 0755); err != nil {
			log.Fatalf("failed to create log dir %q: %v", *LogPath, err)
		}
		var path string
		if fileName != nil {
			path = filepath.Join(*LogPath, fmt.Sprintf("%s.log", logName))
		} else {
			path = filepath.Join(*LogPath, fmt.Sprintf("%s-log-%s.log", logName, time.Now().Format("20060102150405")))
		}
		fd, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal("failed to open log file")
			return nil, err
		}

		cstd := colorable.NewColorableStdout()
		cstdErr := colorable.NewColorableStderr()

		logger = initLogger(logName, max, cstd, fd, false)
		logger.stderr = cstdErr
		return logger, nil

	}
	sysLogInitWorking.Store(false)
	return nil, errors.New("File Path Not Found")
}

func initLogger(logName string, max int, console, file io.Writer, forGin bool) *SysLogger {
	return &SysLogger{
		console:    console,
		stderr:     console,
		file:       file,
		loggerName: logName,
		rotateLock: sync.Mutex{},
		strip:      regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`),
		max:        max,
		GinServer:  forGin,
		counter:    0,
	}
}

// log level
const (
	DEBUG   = 0
	INFO    = 1
	WARNING = 2
	ERROR   = 3
)

type SysLogger struct {
	console    io.Writer
	stderr     io.Writer
	file       io.Writer
	loggerName string
	rotateLock sync.Mutex
	strip      *regexp.Regexp
	GinServer  bool
	max        int
	counter    int
}

func (s *SysLogger) Write(p []byte) (n int, err error) {
	return s.writeTo(s.console, p)
}

func (s *SysLogger) writeTo(console io.Writer, p []byte) (n int, err error) {
	if _, err = console.Write(p); err != nil {
		return len(p), err
	}
	clean := s.strip.ReplaceAll(p, []byte(""))
	if _, err = s.file.Write(clean); err != nil {
		return len(p), err
	}
	return len(p), nil
}

type levelWriter struct {
	logger  *SysLogger
	console io.Writer
}

func (w levelWriter) Write(p []byte) (n int, err error) {
	return w.logger.writeTo(w.console, p)
}

func (s *SysLogger) Debug(msg string) {
	if !DebugMode {
		return
	}
	s.helper(DEBUG, msg)
}

func (s *SysLogger) Info(msg string) {
	s.helper(INFO, msg)
}

func (s *SysLogger) Warn(msg string) {
	s.helper(WARNING, msg)
}

func (s *SysLogger) Error(msg string) {
	s.helper(ERROR, msg)
}

// With Formater

func (s *SysLogger) Debugf(msg string, args ...any) {
	if !DebugMode {
		return
	}
	s.helperf(DEBUG, msg, args...)
}

func (s *SysLogger) Infof(msg string, args ...any) {
	s.helperf(INFO, msg, args...)
}

func (s *SysLogger) Warnf(msg string, args ...any) {
	s.helperf(WARNING, msg, args...)
}

func (s *SysLogger) Errorf(msg string, args ...any) {
	s.helperf(ERROR, msg, args...)
}

func (s *SysLogger) Fatal(msg string, args ...any) {
	t := time.Now()
	prefix := fmt.Sprintf("[%s] FATAL| at %s, ", s.loggerName, t.Format("2006/01/02-15:04:05"))
	m := colorize(prefix, levelColorFatal) + msg
	writer := s.writerForLevel(ERROR)
	_, _ = fmt.Fprintf(writer, m, args...)
	os.Exit(1)
}

func (s *SysLogger) formater(level int) string {
	t := time.Now()
	var prefix string
	switch level {
	case DEBUG:
		prefix = fmt.Sprintf("[%s] DEBUG %v| ", s.loggerName, t.Format("2006/01/02-15:04:05"))
	case INFO:
		prefix = fmt.Sprintf("[%s] INFO  %v| ", s.loggerName, t.Format("2006/01/02-15:04:05"))
	case WARNING:
		prefix = fmt.Sprintf("[%s] WARN  %v| ", s.loggerName, t.Format("2006/01/02-15:04:05"))
	case ERROR:
		prefix = fmt.Sprintf("[%s] ERROR %v| ", s.loggerName, t.Format("2006/01/02-15:04:05"))
	default:
		prefix = fmt.Sprintf("[%s] INFO  %v| ", s.loggerName, t.Format("2006/01/02-15:04:05"))
	}

	return colorize(prefix, levelColor(level))
}

func (s *SysLogger) writerForLevel(level int) io.Writer {
	if s.GinServer {
		if level == INFO || level == DEBUG {
			return gin.DefaultWriter
		}
		return gin.DefaultErrorWriter
	}
	if level == INFO || level == DEBUG {
		return levelWriter{logger: s, console: s.console}
	}
	return levelWriter{logger: s, console: s.stderr}
}

func (s *SysLogger) helper(level int, msg string) {
	writer := s.writerForLevel(level)

	levelPerfix := s.formater(level)
	m := levelPerfix + msg
	_, _ = fmt.Fprint(writer, m+"\n")
	s.counter++
	if s.counter > s.max && !sysLogInitWorking.Load() {
		s.rebuild()
	}
}

func (s *SysLogger) helperf(level int, msg string, args ...any) {
	writer := s.writerForLevel(level)

	levelPerfix := s.formater(level)
	m := levelPerfix + msg
	_, _ = fmt.Fprintf(writer, m, args...)
	fmt.Fprint(writer, "\n")
	s.counter++
	if s.counter > s.max && !sysLogInitWorking.Load() {
		s.rebuild()
	}

}

func (s *SysLogger) selfRotate(logName string, max int) {
	if ok := s.rotateLock.TryLock(); !ok {
		return
	}
	defer s.rotateLock.Unlock()
	defer sysLogInitWorking.Store(false)
	path := filepath.Join(*LogDir, fmt.Sprintf("%s-log-%s.log", logName, time.Now().Format("20060102150405")))
	fd, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal("failed to open log file")
	}
	s.file = fd
}

func (s *SysLogger) rebuild() {
	s.counter = 0
	var f func(logName string, max int)
	sysLogInitWorking.Store(true)
	f = s.selfRotate
	gopool.Go(func() {
		f(s.loggerName, s.max)
	})
}
