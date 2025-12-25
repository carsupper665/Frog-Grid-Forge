package common

import (
	"crypto/rsa"
)

// ./common/constants.go

const (
	Version      = "0.1.0"
	BuildNocolor = "bata-0.0.2b13"
	Build        = ColorBrightYellow + BuildNocolor + ColorReset
	SystemName   = "FGF-idP"
)

const (
	JwtCookieName    = "au4ul4"
	DeviceCookieName = "did"
	JwtExpireSeconds = 24 * 60 * 60 * 7
)

const (
	RequestIdKey = "FGF-Request-Id"
)
const keyChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
const NumberChars = "0123456789"

const (
	RoleGuestUser  = 0
	RoleCommonUser = 1
	RoleAdminUser  = 4
	RoleRootUser   = 6
)

//// 到時候看看可以應用在哪裡
//const (
//	UserStatusEnabled  = 1 // don't use 0, 0 is the default value!
//	UserStatusDisabled = 2 // also don't use 0
//)

// 嘿嘿 我喜歡色彩斑斕的終端:D
const (
	ColorReset         = "\x1b[0m"  // 重置
	ColorBlack         = "\x1b[30m" // 黑
	ColorRed           = "\x1b[31m" // 紅
	ColorGreen         = "\x1b[32m" // 綠
	ColorYellow        = "\x1b[33m" // 黃
	ColorBlue          = "\x1b[34m" // 藍
	ColorMagenta       = "\x1b[35m" // 紫
	ColorCyan          = "\x1b[36m" // 青
	ColorWhite         = "\x1b[37m" // 白
	ColorBrightBlack   = "\x1b[90m" // 亮黑（灰）
	ColorBrightRed     = "\x1b[91m" // 亮紅
	ColorBrightGreen   = "\x1b[92m" // 亮綠
	ColorBrightYellow  = "\x1b[93m" // 亮黃
	ColorBrightBlue    = "\x1b[94m" // 亮藍
	ColorBrightMagenta = "\x1b[95m" // 亮紫
	ColorBrightCyan    = "\x1b[96m" // 亮青
	ColorBrightWhite   = "\x1b[97m" // 亮白

	// 背景色
	BgBlack         = "\x1b[40m"
	BgRed           = "\x1b[41m"
	BgGreen         = "\x1b[42m"
	BgYellow        = "\x1b[43m"
	BgBlue          = "\x1b[44m"
	BgMagenta       = "\x1b[45m"
	BgCyan          = "\x1b[46m"
	BgWhite         = "\x1b[47m"
	BgBrightBlack   = "\x1b[100m"
	BgBrightRed     = "\x1b[101m"
	BgBrightGreen   = "\x1b[102m"
	BgBrightYellow  = "\x1b[103m"
	BgBrightBlue    = "\x1b[104m"
	BgBrightMagenta = "\x1b[105m"
	BgBrightCyan    = "\x1b[106m"
	BgBrightWhite   = "\x1b[107m"
)

var (
	DebugMode bool
	UaFilter  bool
)

var DCWebHookUrl string

var SMTPServer string
var SMTPPort int
var SMTPSSLEnabled bool
var SMTPAccount string
var SMTPFrom string
var SMTPToken string

var (
	GlobalApiRateLimitNum      int
	GlobalApiRateLimitDuration int64
)

var EmailLoginAuthServerList = []string{
	"smtp.sendcloud.net",
	"smtp.azurecomm.net",
}

// RSA keys base64 encoded strings
var (
	RSAPrivateKey *rsa.PrivateKey
	RSAPublicKey  *rsa.PublicKey
)

const (
	// ServiceIDCore = "FGF-idp-core"
	InitialKeyKID = "FGF-idp-key1"
)
