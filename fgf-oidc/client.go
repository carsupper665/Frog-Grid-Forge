// Package fgfoidc handles FGF authorization-code login; services own their users and sessions.
package fgfoidc

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var ErrLogin = errors.New("FGF login is invalid or expired")

type Config struct{ Issuer, ClientID, ClientSecret, RedirectURL, CookieName string }

func FromEnv(get func(string) string, cookieName string) Config {
	return Config{strings.TrimRight(get("FGF_IDP_ISSUER"), "/"), get("FGF_IDP_CLIENT_ID"), get("FGF_IDP_CLIENT_SECRET"), get("FGF_IDP_REDIRECT_URL"), cookieName}
}
func (c Config) Enabled() bool {
	return c.Issuer != "" || c.ClientID != "" || c.ClientSecret != "" || c.RedirectURL != ""
}
func (c Config) Validate() error {
	if c.ClientID == "" || len(c.ClientSecret) < 32 || c.CookieName == "" {
		return errors.New("FGF client ID, secret (32+ characters), and cookie name required")
	}
	for _, raw := range []string{c.Issuer, c.RedirectURL} {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("invalid FGF URL")
		}
		if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")) {
			return errors.New("FGF URLs require HTTPS except on loopback")
		}
	}
	return nil
}
func (c Config) aead() cipher.AEAD {
	key := sha256.Sum256([]byte(c.ClientSecret))
	block, _ := aes.NewCipher(key[:])
	aead, _ := cipher.NewGCM(block)
	return aead
}

// Seal and Open bind encrypted cookies to this issuer, client, purpose and expiry.
func (c Config) Seal(purpose string, value any, ttl time.Duration) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	data, err := json.Marshal(struct {
		Value   any   `json:"v"`
		Expires int64 `json:"exp"`
	}{value, time.Now().Add(ttl).Unix()})
	if err != nil {
		return "", err
	}
	aead := c.aead()
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, data, []byte(c.Issuer+"|"+c.ClientID+"|"+purpose))), nil
}
func (c Config) Open(purpose, value string, target any) error {
	if c.Validate() != nil {
		return ErrLogin
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	aead := c.aead()
	if err != nil || len(raw) < aead.NonceSize() {
		return ErrLogin
	}
	data, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte(c.Issuer+"|"+c.ClientID+"|"+purpose))
	if err != nil {
		return ErrLogin
	}
	var payload struct {
		Value   json.RawMessage `json:"v"`
		Expires int64           `json:"exp"`
	}
	if json.Unmarshal(data, &payload) != nil || payload.Expires <= time.Now().Unix() {
		return ErrLogin
	}
	return json.Unmarshal(payload.Value, target)
}
func (c Config) Cookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(c.RedirectURL, "https://"), SameSite: http.SameSiteLaxMode, MaxAge: maxAge}
}

type transaction struct{ State, Nonce, Verifier string }
type Identity struct {
	Subject  string `json:"sub"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Username string `json:"preferred_username"`
}

func randomValue() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b), err
}
func (c Config) provider(ctx context.Context) (*oidc.Provider, oauth2.Config, error) {
	if err := c.Validate(); err != nil {
		return nil, oauth2.Config{}, err
	}
	p, err := oidc.NewProvider(ctx, c.Issuer)
	if err != nil {
		return nil, oauth2.Config{}, err
	}
	endpoint := p.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	return p, oauth2.Config{ClientID: c.ClientID, ClientSecret: c.ClientSecret, RedirectURL: c.RedirectURL, Scopes: []string{"openid", "profile", "email"}, Endpoint: endpoint}, nil
}
func (c Config) Begin(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	_, oauth, err := c.provider(ctx)
	if err != nil {
		return err
	}
	tx := transaction{}
	for _, field := range []*string{&tx.State, &tx.Nonce, &tx.Verifier} {
		*field, err = randomValue()
		if err != nil {
			return err
		}
	}
	sealed, err := c.Seal("flow", tx, 10*time.Minute)
	if err != nil {
		return err
	}
	challenge := sha256.Sum256([]byte(tx.Verifier))
	target := oauth.AuthCodeURL(tx.State, oidc.Nonce(tx.Nonce), oauth2.SetAuthURLParam("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:])), oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.SetCookie(w, c.Cookie(c.CookieName, sealed, 600))
	http.Redirect(w, r, target, http.StatusFound)
	return nil
}
func (c Config) Exchange(w http.ResponseWriter, r *http.Request, code, state string) (Identity, error) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.SetCookie(w, c.Cookie(c.CookieName, "", -1))
	var tx transaction
	cookie, err := r.Cookie(c.CookieName)
	if err != nil || c.Open("flow", cookie.Value, &tx) != nil || code == "" || state == "" || subtle.ConstantTimeCompare([]byte(state), []byte(tx.State)) != 1 {
		return Identity{}, ErrLogin
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	p, oauth, err := c.provider(ctx)
	if err != nil {
		return Identity{}, err
	}
	token, err := oauth.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", tx.Verifier))
	if err != nil {
		return Identity{}, ErrLogin
	}
	rawID, _ := token.Extra("id_token").(string)
	id, err := p.Verifier(&oidc.Config{ClientID: c.ClientID}).Verify(ctx, rawID)
	if err != nil || id.Subject == "" || id.Nonce != tx.Nonce {
		return Identity{}, ErrLogin
	}
	info, err := p.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil || info.Subject != id.Subject {
		return Identity{}, ErrLogin
	}
	var identity Identity
	if err := info.Claims(&identity); err != nil {
		return Identity{}, err
	}
	if strings.TrimSpace(identity.Email) == "" {
		return Identity{}, ErrLogin
	}
	return identity, nil
}

// IdentityKey stays stable across email/name changes and distinguishes issuers.
func (c Config) IdentityKey(subject string) string {
	digest := sha256.Sum256([]byte(c.Issuer + "\x00" + subject))
	return fmt.Sprintf("%x", digest)
}
