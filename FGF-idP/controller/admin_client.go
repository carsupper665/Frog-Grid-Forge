// controller/admin_client.go
//
// OAuth client (service) management for the admin console. Gated to root:
// registering a redirect URI is enough to harvest authorization codes for every
// user of this identity provider.

package controller

import (
	"FGF-idP/common"
	"FGF-idP/model"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/datatypes"
)

const (
	maxRedirectURIs   = 10
	maxRedirectURILen = 512
	clientSecretLen   = 48 // bcrypt ignores input past 72 bytes
)

// The server only implements the authorization code flow, so these are fixed
// rather than configurable: any other value would produce a client that cannot
// complete a single request.
var (
	fixedGrantTypes    = datatypes.JSON([]byte(`["authorization_code"]`))
	fixedResponseTypes = datatypes.JSON([]byte(`["code"]`))
)

var clientIDPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{3,64}$`)

var errNoRedirectURI = errors.New("redirect_uris must not be empty")

// validateRedirectURIs checks every entry and returns the de-duplicated list.
//
// Only trimming and de-duplication are applied. model.ValiClientWithUrl matches
// the stored value byte for byte, so normalizing the path here would make a
// registered URI stop matching what the client actually sends.
func validateRedirectURIs(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, errNoRedirectURI
	}
	if len(raw) > maxRedirectURIs {
		return nil, errors.New("too many redirect_uris")
	}
	seen := make(map[string]bool, len(raw))
	out := make([]string, 0, len(raw))
	for _, entry := range raw {
		uri := strings.TrimSpace(entry)
		if uri == "" || len(uri) > maxRedirectURILen {
			return nil, errors.New("redirect_uri length out of range")
		}
		// A wildcard registration would let any host under it receive codes.
		if strings.Contains(uri, "*") {
			return nil, errors.New("redirect_uri must not contain a wildcard")
		}
		parsed, err := url.Parse(uri)
		if err != nil || !parsed.IsAbs() || parsed.Host == "" {
			return nil, errors.New("redirect_uri must be an absolute URL")
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return nil, errors.New("redirect_uri scheme must be http or https")
		}
		// RFC 6749 3.1.2 forbids a fragment component.
		if parsed.Fragment != "" || strings.Contains(uri, "#") {
			return nil, errors.New("redirect_uri must not contain a fragment")
		}
		if !common.DebugMode && parsed.Scheme != "https" && !isLoopback(parsed.Hostname()) {
			return nil, errors.New("redirect_uri must use https outside debug mode")
		}
		if seen[uri] {
			continue
		}
		seen[uri] = true
		out = append(out, uri)
	}
	return out, nil
}

func isLoopback(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// clientView is the only client shape the admin API returns. model.Client must
// never be serialized directly: it carries SecretHash.
type clientView struct {
	ClientID     string    `json:"client_id"`
	Name         string    `json:"name"`
	RedirectURIs []string  `json:"redirect_uris"`
	Scope        string    `json:"scope"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func newClientView(client model.Client) clientView {
	uris := []string{}
	if len(client.RedirectURIs) > 0 {
		_ = json.Unmarshal(client.RedirectURIs, &uris)
	}
	return clientView{
		ClientID: client.ClientID, Name: client.Name, RedirectURIs: uris,
		Scope: client.Scope, CreatedAt: client.CreatedAt, UpdatedAt: client.UpdatedAt,
	}
}

type clientReq struct {
	ClientID     string   `json:"client_id"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Scope        string   `json:"scope"`
}

func AdminListClients(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	page, size := pageParams(c)
	clients, hasMore, err := model.ListClients(c.Request.Context(), c.Query("q"), page, size)
	if err != nil {
		common.LogError(c.Request.Context(), "admin list clients: "+err.Error())
		fail(c, http.StatusInternalServerError, "server_error")
		return
	}
	views := make([]clientView, 0, len(clients))
	for _, client := range clients {
		views = append(views, newClientView(client))
	}
	c.JSON(http.StatusOK, gin.H{"clients": views, "has_more": hasMore})
}

func AdminGetClient(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	client, err := loadClient(c)
	if err != nil {
		return
	}
	c.JSON(http.StatusOK, newClientView(client))
}

// AdminCreateClient registers a service. The generated secret is returned once
// and never again: only its bcrypt hash is stored.
func AdminCreateClient(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	var req clientReq
	if !bindClientReq(c, &req) {
		return
	}
	if !clientIDPattern.MatchString(req.ClientID) {
		fail(c, http.StatusBadRequest, "invalid_client_id")
		return
	}
	name, ok := validClientName(req.Name)
	if !ok {
		fail(c, http.StatusBadRequest, "invalid_request")
		return
	}
	if !isValidOIDCScope(req.Scope) {
		fail(c, http.StatusBadRequest, "invalid_scope")
		return
	}
	uris, err := validateRedirectURIs(req.RedirectURIs)
	if err != nil {
		fail(c, http.StatusBadRequest, "invalid_redirect_uri")
		return
	}
	secret, hash, err := newClientSecret()
	if err != nil {
		common.LogError(c.Request.Context(), "admin client secret: "+err.Error())
		fail(c, http.StatusInternalServerError, "server_error")
		return
	}
	encoded, _ := json.Marshal(uris)
	client := model.Client{
		ClientID:      req.ClientID,
		Name:          name,
		SecretHash:    hash,
		RedirectURIs:  datatypes.JSON(encoded),
		Scope:         req.Scope,
		GrantTypes:    fixedGrantTypes,
		ResponseTypes: fixedResponseTypes,
	}
	if err := model.CreateClient(c.Request.Context(), &client); err != nil {
		if errors.Is(err, model.ErrClientExists) {
			fail(c, http.StatusConflict, "client_exists")
			return
		}
		common.LogError(c.Request.Context(), "admin create client: "+err.Error())
		fail(c, http.StatusInternalServerError, "server_error")
		return
	}
	common.LogInfo(c.Request.Context(), "admin create client: "+client.ClientID)
	view := newClientView(client)
	c.JSON(http.StatusCreated, gin.H{"client": view, "client_secret": secret})
}

func AdminUpdateClient(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	var req clientReq
	if !bindClientReq(c, &req) {
		return
	}
	updates := map[string]any{}
	if strings.TrimSpace(req.Name) != "" {
		name, ok := validClientName(req.Name)
		if !ok {
			fail(c, http.StatusBadRequest, "invalid_request")
			return
		}
		updates["name"] = name
	}
	if req.Scope != "" {
		if !isValidOIDCScope(req.Scope) {
			fail(c, http.StatusBadRequest, "invalid_scope")
			return
		}
		updates["scope"] = req.Scope
	}
	if req.RedirectURIs != nil {
		uris, err := validateRedirectURIs(req.RedirectURIs)
		if err != nil {
			fail(c, http.StatusBadRequest, "invalid_redirect_uri")
			return
		}
		encoded, _ := json.Marshal(uris)
		updates["redirect_uris"] = datatypes.JSON(encoded)
	}
	clientID := c.Param("client_id")
	if err := model.UpdateClient(c.Request.Context(), clientID, updates); err != nil {
		respondClientError(c, err, "admin update client")
		return
	}
	common.LogInfo(c.Request.Context(), "admin update client: "+clientID)
	client, err := loadClient(c)
	if err != nil {
		return
	}
	c.JSON(http.StatusOK, newClientView(client))
}

// AdminRotateClientSecret issues a replacement secret, returned once.
func AdminRotateClientSecret(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	secret, hash, err := newClientSecret()
	if err != nil {
		common.LogError(c.Request.Context(), "admin client secret: "+err.Error())
		fail(c, http.StatusInternalServerError, "server_error")
		return
	}
	clientID := c.Param("client_id")
	if err := model.SetClientSecret(c.Request.Context(), clientID, hash); err != nil {
		respondClientError(c, err, "admin rotate secret")
		return
	}
	common.LogInfo(c.Request.Context(), "admin rotate client secret: "+clientID)
	c.JSON(http.StatusOK, gin.H{"client_secret": secret})
}

func AdminDeleteClient(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	clientID := c.Param("client_id")
	if err := model.DeleteClient(c.Request.Context(), clientID); err != nil {
		respondClientError(c, err, "admin delete client")
		return
	}
	common.LogInfo(c.Request.Context(), "admin delete client: "+clientID)
	c.Status(http.StatusNoContent)
}

func bindClientReq(c *gin.Context, req *clientReq) bool {
	if !wantsJSON(c) {
		fail(c, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return false
	}
	if err := c.ShouldBindJSON(req); err != nil {
		fail(c, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}

func validClientName(raw string) (string, bool) {
	name := strings.TrimSpace(raw)
	if name == "" || len(name) > 64 {
		return "", false
	}
	return name, true
}

func newClientSecret() (secret, hash string, err error) {
	secret = common.GetRandomString(clientSecretLen)
	hash, err = common.Password2Hash(secret)
	return secret, hash, err
}

func loadClient(c *gin.Context) (model.Client, error) {
	client, err := model.GetClient(c.Request.Context(), c.Param("client_id"))
	if err != nil {
		respondClientError(c, err, "admin client lookup")
		return model.Client{}, err
	}
	return client, nil
}

func respondClientError(c *gin.Context, err error, what string) {
	if errors.Is(err, model.ErrClientNotFound) {
		fail(c, http.StatusNotFound, "not_found")
		return
	}
	common.LogError(c.Request.Context(), what+": "+err.Error())
	fail(c, http.StatusInternalServerError, "server_error")
}
