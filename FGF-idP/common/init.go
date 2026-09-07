package common

// ./common/init.go

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

var (
	Port                = 3000
	SessionSecret       = uuid.New().String()
	CryptoSecret        = uuid.New().String()
	HMACSecret          = "HMACSecret"
	LogDir              = flag.String("log-dir", "./logs", "specify the log directory")
	MemoryCacheEnabled  bool
	SyncFrequency       int
	BatchUpdateInterval int
	BatchUpdateEnabled  = false
	RelayTimeout        int
	Logger              *SysLogger
)

var (
	SQLitePath   = "DB.db?_busy_timeout=5000"
	SQLDsn       = ""
	SQLLogDsn    = ""
	MaxIdleConns = 100
	MaxOpenConns = 100
	Lifetime     = 60 // in minutes
)

func InitLogger() {
	logger, err := NewSysLogger("FGF-idP", nil, 8000)
	if err != nil {
		fmt.Println("InitLogger err:", err)
		os.Exit(0)
	}
	Logger = logger
}

func LoadEnv() {

	if os.Getenv("SESSION_SECRET") != "" {
		ss := os.Getenv("SESSION_SECRET")
		if ss == "random_string" {
			log.Println("WARNING: SESSION_SECRET is set to the default value 'random_string', please change it to a random string.")
			log.Fatal("Please set SESSION_SECRET to a random string.")
		} else {
			SessionSecret = ss
		}
	}
	if os.Getenv("CRYPTO_SECRET") != "" {
		CryptoSecret = os.Getenv("CRYPTO_SECRET")
	} else {
		CryptoSecret = SessionSecret
	}

	if os.Getenv("HMAC_SECRET") != "" {
		HMACSecret = os.Getenv("HMAC_SECRET")
	} else {
		HMACSecret = SessionSecret
	}

	if os.Getenv("SQLITE_PATH") != "" {
		SQLitePath = os.Getenv("SQLITE_PATH")
	}

	if *LogDir != "" {
		var err error
		*LogDir, err = filepath.Abs(*LogDir)
		if err != nil {
			log.Fatal(err)
		}
		if _, err := os.Stat(*LogDir); os.IsNotExist(err) {
			err = os.Mkdir(*LogDir, 0777)
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	// Initialize variables from constants.go that were using environment variables
	DebugMode = os.Getenv("DEBUG") == "true"
	MemoryCacheEnabled = os.Getenv("MEMORY_CACHE_ENABLED") == "true"
	UaFilter = os.Getenv("UA_FILTER") == "true"
	Port = GetEnvOrDefault("PORT", 3000)
	backendBaseURL := strings.TrimSuffix(GetEnvOrDefaultString("BACKEND_BASE_URL", fmt.Sprintf("http://localhost:%d", Port)), "/")
	Issuer = backendBaseURL
	AccessTokenExpireSeconds = GetEnvOrDefault("ACCESS_TOKEN_TTL_SECONDS", JwtExpireSeconds)
	SessionCookieExpireSeconds = GetEnvOrDefault("SESSION_COOKIE_TTL_SECONDS", 30*24*60*60)
	DeviceCookieExpireSeconds = GetEnvOrDefault("DEVICE_COOKIE_TTL_SECONDS", 360*24*60*60)
	CookieSecure = GetEnvOrDefaultBool("COOKIE_SECURE", strings.HasPrefix(backendBaseURL, "https://"))

	// Initialize variables with GetEnvOrDefault
	SyncFrequency = GetEnvOrDefault("SYNC_FREQUENCY", 60)
	BatchUpdateInterval = GetEnvOrDefault("BATCH_UPDATE_INTERVAL", 5)
	RelayTimeout = GetEnvOrDefault("RELAY_TIMEOUT", 0)

	GlobalApiRateLimitNum = GetEnvOrDefault("GLOBAL_API_RATE_LIMIT", 60)
	GlobalApiRateLimitDuration = int64(GetEnvOrDefault("GLOBAL_API_RATE_LIMIT_DURATION", 60))
	DCWebHookUrl = GetEnvOrDefaultString("DC_WEBHOOK_URL", "")
	SetUpSMTP()
	SetUpDatabase()
}

func SetUpDatabase() {
	SQLDsn = GetEnvOrDefaultString("SQL_DSN", "")
	SQLLogDsn = GetEnvOrDefaultString("SQL_LOG_DSN", "")
	MaxIdleConns = GetEnvOrDefault("DB_MAX_IDLE_CONNS", 150)
	MaxOpenConns = GetEnvOrDefault("DB_MAX_OPEN_CONNS", 150)
	Lifetime = GetEnvOrDefault("DB_CONN_LIFETIME", 60)
}

func SetUpSMTP() {
	SMTPServer = GetEnvOrDefaultString("SMTP_SERVER", "")
	SMTPPort = GetEnvOrDefault("SMTP_PORT", 587)
	SMTPSSLEnabled = GetEnvOrDefaultBool("SMTP_SSL_ENABLED", false)
	SMTPAccount = GetEnvOrDefaultString("SMTP_ACCOUNT", "")
	SMTPFrom = GetEnvOrDefaultString("SMTP_FROM", "")
	SMTPToken = GetEnvOrDefaultString("SMTP_TOKEN", "")
}
