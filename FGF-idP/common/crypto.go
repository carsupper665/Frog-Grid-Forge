package common

// common/crypto.go

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

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

func GenJWT(uid uint, deviceHash, aud, email string) (string, error) {
	claims := jwt.MapClaims{
		"iss":    GetEnvOrDefaultString("FRONTEND_BASE_URL", ""),
		"sub":    uid,
		"aud":    aud,
		"email":  email,
		"device": deviceHash,
		"exp":    time.Now().Add(time.Hour).Unix(),
		"iat":    time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	idTokenStr, err := token.SignedString(CryptoSecret)
	return idTokenStr, err
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
