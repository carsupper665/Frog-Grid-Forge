package fgfoidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	jose "github.com/go-jose/go-jose/v3"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func testConfig() Config {
	return Config{"http://127.0.0.1:15515", "test-client", strings.Repeat("s", 40), "http://127.0.0.1:3000/callback", "test_flow"}
}
func TestCookieIsolation(t *testing.T) {
	cfg := testConfig()
	sealed, err := cfg.Seal("flow", transaction{"state", "nonce", "verifier"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var tx transaction
	if cfg.Open("flow", sealed, &tx) != nil || tx.State != "state" {
		t.Fatal("cookie round trip failed")
	}
	if cfg.Open("session", sealed, &tx) == nil {
		t.Fatal("accepted wrong purpose")
	}
	other := cfg
	other.ClientID = "another-client"
	if other.Open("flow", sealed, &tx) == nil {
		t.Fatal("accepted another client")
	}
	other = cfg
	other.Issuer = "http://127.0.0.1:15516"
	if other.Open("flow", sealed, &tx) == nil {
		t.Fatal("accepted another issuer")
	}
	raw := []byte(sealed)
	raw[len(raw)/2] ^= 1
	if cfg.Open("flow", string(raw), &tx) == nil {
		t.Fatal("accepted tampered cookie")
	}
	expired, _ := cfg.Seal("flow", tx, -time.Minute)
	if cfg.Open("flow", expired, &tx) == nil {
		t.Fatal("accepted expired cookie")
	}
	for _, bad := range []string{"", "not-a-cookie", "AA"} {
		if cfg.Open("flow", bad, &tx) == nil {
			t.Fatal("accepted malformed cookie")
		}
	}
}
func TestConfigRejectsUnsafeURLs(t *testing.T) {
	for _, raw := range []string{"http://example.com/callback", "https://user@example.com/callback", "https://example.com/callback#fragment", "/callback", "javascript:alert(1)"} {
		cfg := testConfig()
		cfg.RedirectURL = raw
		if cfg.Validate() == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}
func TestAuthorizationCodeFlow(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "test"))
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"success", "state", "nonce", "audience", "issuer", "expired", "subject", "signature", "replay", "missing_cookie"} {
		t.Run(scenario, func(t *testing.T) {
			cfg := testConfig()
			var nonce, challenge string
			used := false
			tokenCalls := 0
			mux := http.NewServeMux()
			server := httptest.NewServer(mux)
			defer server.Close()
			cfg.Issuer = server.URL
			mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{"issuer": server.URL, "authorization_endpoint": server.URL + "/authorize", "token_endpoint": server.URL + "/token", "userinfo_endpoint": server.URL + "/userinfo", "jwks_uri": server.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
			})
			mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}}})
			})
			mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
				tokenCalls++
				r.ParseForm()
				if r.Form.Get("client_secret") != cfg.ClientSecret || r.Form.Get("client_id") != cfg.ClientID || r.Form.Get("redirect_uri") != cfg.RedirectURL || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "code" {
					t.Error("invalid exchange contract")
					http.Error(w, "bad request", 400)
					return
				}
				// Inspect the exact S256 verifier sent to the token endpoint.
				digest := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
				if base64.RawURLEncoding.EncodeToString(digest[:]) != challenge {
					t.Error("missing PKCE")
				}
				if used {
					http.Error(w, "used code", 400)
					return
				}
				used = true
				claims := map[string]any{"iss": server.URL, "aud": cfg.ClientID, "sub": "owner-1", "nonce": nonce, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()}
				switch scenario {
				case "nonce":
					claims["nonce"] = "wrong"
				case "audience":
					claims["aud"] = "other"
				case "issuer":
					claims["iss"] = "https://wrong.example"
				case "expired":
					claims["exp"] = time.Now().Add(-time.Hour).Unix()
				}
				payload, _ := json.Marshal(claims)
				signed, _ := signer.Sign(payload)
				raw, _ := signed.CompactSerialize()
				if scenario == "signature" {
					parts := strings.Split(raw, ".")
					parts[2] = "AAAA"
					raw = strings.Join(parts, ".")
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "id_token": raw, "expires_in": 60})
			})
			mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer access" {
					t.Error("missing bearer")
				}
				sub := "owner-1"
				if scenario == "subject" {
					sub = "other"
				}
				json.NewEncoder(w).Encode(Identity{Subject: sub, Email: "owner@example.com", Name: "Owner", Role: 6})
			})
			start := httptest.NewRecorder()
			if err := cfg.Begin(start, httptest.NewRequest("GET", "/login", nil)); err != nil {
				t.Fatal(err)
			}
			dest, _ := url.Parse(start.Header().Get("Location"))
			nonce = dest.Query().Get("nonce")
			challenge = dest.Query().Get("code_challenge")
			if start.Code != 302 || nonce == "" || dest.Query().Get("code_challenge_method") != "S256" || dest.Query().Get("scope") != "openid profile email" {
				t.Fatal("invalid authorize request")
			}
			cookie := start.Result().Cookies()[0]
			if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
				t.Fatal("unsafe cookie")
			}
			request := httptest.NewRequest("POST", "/callback", nil)
			if scenario != "missing_cookie" {
				request.AddCookie(cookie)
			}
			state := dest.Query().Get("state")
			if scenario == "state" {
				state = "wrong"
			}
			identity, err := cfg.Exchange(httptest.NewRecorder(), request, "code", state)
			if scenario == "success" || scenario == "replay" {
				if err != nil || identity.Subject != "owner-1" || identity.Role != 6 {
					t.Fatalf("login failed: %v", err)
				}
			} else if err == nil {
				t.Fatal("accepted invalid login")
			}
			if scenario == "replay" {
				if _, err := cfg.Exchange(httptest.NewRecorder(), request, "code", state); err == nil {
					t.Fatal("accepted replay")
				}
			}
			if (scenario == "state" || scenario == "missing_cookie") && tokenCalls != 0 {
				t.Fatal("exchanged code without browser binding")
			}
		})
	}
}
