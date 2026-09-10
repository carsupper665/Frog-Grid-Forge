package common

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWTValidation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	oldPrivate, oldPublic := RSAPrivateKey, RSAPublicKey
	RSAPrivateKey, RSAPublicKey = key, &key.PublicKey
	t.Cleanup(func() { RSAPrivateKey, RSAPublicKey = oldPrivate, oldPublic })
	for _, tc := range []struct {
		name   string
		change func(jwt.MapClaims)
		valid  bool
	}{
		{"valid", func(jwt.MapClaims) {}, true},
		{"expired", func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }, false},
		{"missing expiry", func(c jwt.MapClaims) { delete(c, "exp") }, false},
		{"invalid expiry", func(c jwt.MapClaims) { c["exp"] = "tomorrow" }, false},
		{"wrong issuer", func(c jwt.MapClaims) { c["iss"] = "https://other.example" }, false},
		{"missing issuer", func(c jwt.MapClaims) { delete(c, "iss") }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{"iss": Issuer, "exp": time.Now().Add(time.Hour).Unix()}
			tc.change(claims)
			token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
			if err != nil {
				t.Fatal(err)
			}
			_, err = GetJWTPayload(token)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
		})
	}
	hmacToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": Issuer, "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte("untrusted"))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{hmacToken, strings.Repeat(".", 10000)} {
		if _, err := GetJWTPayload(bad); err == nil {
			t.Fatal("accepted invalid token")
		}
	}
	first, err := GenerateSessionToken(1, "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateSessionToken(1, "test")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("new session reuses a revocable token")
	}
}

func TestRandomCredentialFormat(t *testing.T) {
	for _, tc := range []struct {
		generate func(int) string
		alphabet string
	}{
		{GetRandomString, keyChars}, {GetRandomIntString, NumberChars},
	} {
		for _, length := range []int{0, 1, 6, 32, 256} {
			value := tc.generate(length)
			if len(value) != length {
				t.Fatalf("length=%d, want %d", len(value), length)
			}
			if strings.Trim(value, tc.alphabet) != "" {
				t.Fatal("unexpected credential characters")
			}
		}
	}
}

func TestEmailVerificationTokensAreUnique(t *testing.T) {
	first, err := GenEmailSignedToken("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenEmailSignedToken("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("verification tokens collide across requests")
	}
	payload, err := VerifySignedToken(first)
	if err != nil || payload.UserEmail != "user@example.com" {
		t.Fatalf("verification roundtrip: %v", err)
	}
}
