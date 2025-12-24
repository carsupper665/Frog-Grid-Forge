package common

// common/crypto.go

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

var Issuer = GetEnvOrDefaultString("FRONTEND_BASE_URL", "http://127.0.0.1:3000")
var ErrKeyNotFound = errors.New("signing key not found")

func GenerateHMACWithKey(key []byte, data string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func GenerateHMAC(data string) string {
	h := hmac.New(sha256.New, []byte(CryptoSecret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func Password2Hash(password string) (string, error) {
	passwordBytes := []byte(password)
	hashedPassword, err := bcrypt.GenerateFromPassword(passwordBytes, bcrypt.DefaultCost)
	return string(hashedPassword), err
}

func ValidatePasswordAndHash(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func GenerateDeviceIDWithIP(ip string) string {
	// 1) 隨機 8 byte
	randBytes := make([]byte, 8)
	if _, err := rand.Read(randBytes); err != nil {
		SysError("Failed to generate random bytes for device ID: " + err.Error())
		return "" // 失敗就回空
	}

	// 2) IP 的 SHA-256 前 8 byte
	h := sha256.Sum256([]byte(ip))
	ipPart := h[:8]

	// 3) 拼接並回傳
	id := append(randBytes, ipPart...)
	return hex.EncodeToString(id)
}

func GenerateAccessToken(userID uint, clientID, audience, scope string) (string, error) {
	now := time.Now()

	claims := jwt.MapClaims{
		"iss":       Issuer,             // 你的 IdP base URL，例如 "https://idp.fgf.local"
		"sub":       fmt.Sprint(userID), // 使用者 ID（字串）
		"aud":       audience,           // target API / resource server
		"client_id": clientID,           // 哪個 client 要的 token
		"scope":     scope,              // "openid profile ..."
		"exp":       now.Add(JwtExpireSeconds).Unix(),
		"iat":       now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(RSAPrivateKey) // 注意這裡要的是 *rsa.PrivateKey 物件，不是 PEM 字串
	return signed, err
}

func GenerateIDToken(userID uint, clientID, nonce string) (string, error) {
	if RSAPrivateKey == nil {
		return "", fmt.Errorf("RSAPrivateKey is nil; make sure keys are initialized")
	}

	now := time.Now()

	claims := jwt.MapClaims{
		"iss": Issuer,             // IdP 的 Issuer URL
		"sub": fmt.Sprint(userID), // 使用者 ID，要是字串
		"aud": clientID,           // 這顆 ID Token 給哪個 client 用
		"exp": now.Add(JwtExpireSeconds).Unix(),
		"iat": now.Unix(),
		// 可以視需求加 "auth_time": authTime.Unix(),
	}

	// 如果 Auth Request 有帶 nonce，就回寫進 ID Token
	if nonce != "" {
		claims["nonce"] = nonce
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	signed, err := token.SignedString(RSAPrivateKey)
	if err != nil {
		return "", fmt.Errorf("signing id_token failed: %w", err)
	}
	return signed, nil
}

// GenerateRSAKeyPair 會在當前目錄產生：
//   - idp-signing-key.pem      (私鑰, 0600)
//   - idp-signing-key.pub.pem  (公鑰, 0644)
func GenerateRSAKeyPair(prive, pub string) error {
	// 1) 生成 2048-bit RSA 私鑰
	// save to ./keys
	SysLog("Generating new RSA key pair...")
	err := os.Mkdir("keys", 0o755)
	if err != nil {
		return err
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate rsa key: %w", err)
	}

	// 2) 私鑰轉成 PKCS#1 DER
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// 3) 包成 PEM block
	privBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privDER,
	}

	// 4) 寫入私鑰檔案（權限要嚴格一點）
	if err := os.WriteFile(prive, pem.EncodeToMemory(privBlock), 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	// 5) 從私鑰取出公鑰，轉成 PKIX DER
	pubDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}

	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	}

	// 6) 寫入公鑰檔案
	if err := os.WriteFile(pub, pem.EncodeToMemory(pubBlock), 0o644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	return nil
}

func LoadKey(privPath, pubPath string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privPEM, err := os.ReadFile(privPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, ErrKeyNotFound
		}
		return nil, nil, fmt.Errorf("read private key: %w", err)
	}

	pubPEM, err := os.ReadFile(pubPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, ErrKeyNotFound
		}
		return nil, nil, fmt.Errorf("read public key: %w", err)
	}

	privBlock, _ := pem.Decode(privPEM)
	if privBlock == nil {
		return nil, nil, fmt.Errorf("invalid private key PEM")
	}

	var privKey *rsa.PrivateKey

	switch privBlock.Type {
	case "RSA PRIVATE KEY":
		// PKCS#1
		k, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse PKCS1 private key: %w", err)
		}
		privKey = k
	case "PRIVATE KEY":
		// PKCS#8
		keyAny, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse PKCS8 private key: %w", err)
		}
		k, ok := keyAny.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("private key is not RSA")
		}
		privKey = k
	default:
		return nil, nil, fmt.Errorf("unsupported private key type: %s", privBlock.Type)
	}

	pubBlock, _ := pem.Decode(pubPEM)
	if pubBlock == nil {
		return nil, nil, fmt.Errorf("invalid public key PEM")
	}

	if pubBlock.Type != "PUBLIC KEY" {
		return nil, nil, fmt.Errorf("unsupported public key type: %s", pubBlock.Type)
	}

	pubAny, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse public key: %w", err)
	}

	pubKey, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("public key is not RSA")
	}

	return privKey, pubKey, nil
}

func GetJWTPayload(token string) (map[string]interface{}, error) {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, jwt.NewValidationError("unexpected signing method", jwt.ValidationErrorSignatureInvalid)
		}
		return []byte(CryptoSecret), nil
	})

	if err != nil || !parsedToken.Valid {
		return nil, err // 解析失敗或無效
	}

	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok {
		payload := make(map[string]interface{})
		for k, v := range claims {
			payload[k] = v
		}
		return payload, nil
	}

	return nil, jwt.NewValidationError("invalid token claims", jwt.ValidationErrorClaimsInvalid)
}

type VerifyPayload struct {
	UserEmail string `json:"user_email"`
	Exp       int64  `json:"exp"` // min
}

func GenEmailSignedToken(userEmail string) (string, error) {
	payload := VerifyPayload{
		UserEmail: userEmail,
		Exp:       time.Now().Add(5 * time.Minute).Unix(),
	}
	data, _ := json.Marshal(payload)
	key := []byte(CryptoSecret)
	// HMAC-SHA256 Signature
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	sig := mac.Sum(nil)
	token := base64.RawURLEncoding.EncodeToString(data) + "." +
		base64.RawURLEncoding.EncodeToString(sig)
	return token, nil
}

func VerifySignedToken(token string) (*VerifyPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid token")
	}

	data, _ := base64.RawURLEncoding.DecodeString(parts[0])
	sig, _ := base64.RawURLEncoding.DecodeString(parts[1])

	key := []byte(CryptoSecret)
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	expected := mac.Sum(nil)

	if !hmac.Equal(sig, expected) {
		return nil, fmt.Errorf("invalid signature")
	}

	var payload VerifyPayload
	_ = json.Unmarshal(data, &payload)

	if time.Now().Unix() > payload.Exp {
		return nil, fmt.Errorf("token expired")
	}

	return &payload, nil
}

func VerifyPKCE(codeVerifier, codeChallenge, method string) bool {
	switch method {
	case "S256":
		h := sha256.New()
		h.Write([]byte(codeVerifier))
		hashed := h.Sum(nil)
		encoded := base64.RawURLEncoding.EncodeToString(hashed)
		return encoded == codeChallenge
	case "plain":
		return codeVerifier == codeChallenge
	default:
		return false
	}
}
