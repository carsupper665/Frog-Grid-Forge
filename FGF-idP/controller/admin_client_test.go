package controller

import (
	"FGF-idP/model"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// TestValidateRedirectURIs is the security core of service registration: a
// redirect URI that slips through here can collect authorization codes for
// every user of this provider. setupControllerTest runs with DEBUG=false, so
// the https requirement is active.
func TestValidateRedirectURIs(t *testing.T) {
	setupControllerTest(t)

	for _, tc := range []struct {
		name string
		in   []string
		want []string
	}{
		{name: "https", in: []string{"https://app.example.com/cb"}, want: []string{"https://app.example.com/cb"}},
		{name: "loopback http", in: []string{"http://localhost:3000/cb"}, want: []string{"http://localhost:3000/cb"}},
		{name: "loopback ipv4", in: []string{"http://127.0.0.1:8080/cb"}, want: []string{"http://127.0.0.1:8080/cb"}},
		{name: "trimmed", in: []string{"  https://a.example.com/cb  "}, want: []string{"https://a.example.com/cb"}},
		{name: "deduplicated", in: []string{"https://a.example.com/cb", "https://a.example.com/cb"}, want: []string{"https://a.example.com/cb"}},

		{name: "empty list", in: nil},
		{name: "plain http host", in: []string{"http://evil.example.com/cb"}},
		{name: "fragment", in: []string{"https://a.example.com/cb#token"}},
		{name: "wildcard host", in: []string{"https://*.example.com/cb"}},
		{name: "wildcard path", in: []string{"https://a.example.com/*"}},
		{name: "non http scheme", in: []string{"ftp://a.example.com/cb"}},
		{name: "custom scheme", in: []string{"javascript:alert(1)"}},
		{name: "relative", in: []string{"/callback"}},
		{name: "no host", in: []string{"https:///cb"}},
		{name: "blank entry", in: []string{"   "}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateRedirectURIs(tc.in)
			if tc.want == nil {
				if err == nil {
					t.Fatalf("expected rejection, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected rejection: %v", err)
			}
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}

	t.Run("too many", func(t *testing.T) {
		many := make([]string, 0, maxRedirectURIs+1)
		for i := 0; i <= maxRedirectURIs; i++ {
			many = append(many, fmt.Sprintf("https://a%d.example.com/cb", i))
		}
		if _, err := validateRedirectURIs(many); err == nil {
			t.Fatal("expected rejection past the redirect URI cap")
		}
	})
}

func createClientBody(clientID string) string {
	return fmt.Sprintf(
		`{"client_id":%q,"name":"Test Service","scope":"openid profile email","redirect_uris":["https://app.example.com/cb"]}`,
		clientID)
}

// TestAdminCreateClientReturnsSecretOnce covers the whole secret lifecycle: the
// plaintext appears in the creation response and nowhere else, because storage
// only holds a bcrypt hash.
func TestAdminCreateClientReturnsSecretOnce(t *testing.T) {
	env := setupAdminTest(t)

	resp := adminRequest(t, env, http.MethodPost, "/x/admin/clients", createClientBody("svc-one"), env.user)
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", resp.Code, resp.Body.String())
	}
	secret, _ := decodeJSONMap(t, resp)["client_secret"].(string)
	if len(secret) != clientSecretLen {
		t.Fatalf("expected a generated secret, got %q", secret)
	}

	ok, msg, err := model.ValiClient("svc-one", "https://app.example.com/cb", secret)
	if err != nil || !ok {
		t.Fatalf("returned secret does not authenticate: ok=%v msg=%q err=%v", ok, msg, err)
	}

	for _, target := range []string{"/x/admin/clients", "/x/admin/clients/svc-one"} {
		resp := adminRequest(t, env, http.MethodGet, target, "", env.user)
		if resp.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d body=%s", target, resp.Code, resp.Body.String())
		}
		for _, forbidden := range []string{"client_secret", "secret_hash", secret} {
			if strings.Contains(resp.Body.String(), forbidden) {
				t.Fatalf("%s leaks %q: %s", target, forbidden, resp.Body.String())
			}
		}
	}
}

// TestAdminCreateClientRejectsWrongRedirectURI checks that ValiClient honours
// the redirect URI verdict rather than letting a correct secret override it.
func TestAdminClientRejectsUnregisteredRedirectURI(t *testing.T) {
	env := setupAdminTest(t)
	resp := adminRequest(t, env, http.MethodPost, "/x/admin/clients", createClientBody("svc-two"), env.user)
	secret, _ := decodeJSONMap(t, resp)["client_secret"].(string)

	ok, _, err := model.ValiClient("svc-two", "https://attacker.example.com/cb", secret)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if ok {
		t.Fatal("a correct secret must not excuse an unregistered redirect URI")
	}
}

func TestAdminCreateClientRejectsBadInput(t *testing.T) {
	env := setupAdminTest(t)

	for _, tc := range []struct {
		name, body, wantErr string
		status              int
	}{
		{
			name:   "bad client id",
			body:   `{"client_id":"a b","name":"X","scope":"openid","redirect_uris":["https://a.example.com/cb"]}`,
			status: http.StatusBadRequest, wantErr: "invalid_client_id",
		},
		{
			name:   "bad scope",
			body:   `{"client_id":"svc-scope","name":"X","scope":"openid admin","redirect_uris":["https://a.example.com/cb"]}`,
			status: http.StatusBadRequest, wantErr: "invalid_scope",
		},
		{
			name:   "bad redirect uri",
			body:   `{"client_id":"svc-uri","name":"X","scope":"openid","redirect_uris":["http://evil.example.com/cb"]}`,
			status: http.StatusBadRequest, wantErr: "invalid_redirect_uri",
		},
		{
			name:   "empty name",
			body:   `{"client_id":"svc-name","name":"  ","scope":"openid","redirect_uris":["https://a.example.com/cb"]}`,
			status: http.StatusBadRequest, wantErr: "invalid_request",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := adminRequest(t, env, http.MethodPost, "/x/admin/clients", tc.body, env.user)
			if resp.Code != tc.status {
				t.Fatalf("expected %d, got %d body=%s", tc.status, resp.Code, resp.Body.String())
			}
			assertJSONError(t, resp, tc.wantErr)
		})
	}
}

func TestAdminCreateClientRejectsDuplicate(t *testing.T) {
	env := setupAdminTest(t)
	if resp := adminRequest(t, env, http.MethodPost, "/x/admin/clients", createClientBody("svc-dup"), env.user); resp.Code != http.StatusCreated {
		t.Fatalf("first create failed: %d body=%s", resp.Code, resp.Body.String())
	}
	resp := adminRequest(t, env, http.MethodPost, "/x/admin/clients", createClientBody("svc-dup"), env.user)
	if resp.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d body=%s", resp.Code, resp.Body.String())
	}
	assertJSONError(t, resp, "client_exists")
}

func TestAdminRotateClientSecretInvalidatesTheOldOne(t *testing.T) {
	env := setupAdminTest(t)
	resp := adminRequest(t, env, http.MethodPost, "/x/admin/clients", createClientBody("svc-rot"), env.user)
	oldSecret, _ := decodeJSONMap(t, resp)["client_secret"].(string)

	resp = adminRequest(t, env, http.MethodPost, "/x/admin/clients/svc-rot/secret", "", env.user)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	newSecret, _ := decodeJSONMap(t, resp)["client_secret"].(string)
	if newSecret == "" || newSecret == oldSecret {
		t.Fatalf("expected a fresh secret, got %q", newSecret)
	}

	const uri = "https://app.example.com/cb"
	if ok, _, _ := model.ValiClient("svc-rot", uri, oldSecret); ok {
		t.Fatal("the rotated-out secret still authenticates")
	}
	if ok, msg, err := model.ValiClient("svc-rot", uri, newSecret); !ok {
		t.Fatalf("the new secret does not authenticate: msg=%q err=%v", msg, err)
	}
}

func TestAdminRotateClientSecretRejectsNonJSONWithoutChangingSecret(t *testing.T) {
	env := setupAdminTest(t)
	resp := adminRequest(t, env, http.MethodPost, "/x/admin/clients", createClientBody("svc-no-form-rotate"), env.user)
	oldSecret, _ := decodeJSONMap(t, resp)["client_secret"].(string)

	for _, tc := range []struct {
		name, body, contentType string
	}{
		{name: "form", body: "rotate=true", contentType: "application/x-www-form-urlencoded"},
		{name: "text", body: "rotate", contentType: "text/plain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := performRequest(t, env.router, http.MethodPost, "/x/admin/clients/svc-no-form-rotate/secret",
				tc.body, tc.contentType, []*http.Cookie{cookieFor(t, env.user)})
			if resp.Code != http.StatusUnsupportedMediaType {
				t.Fatalf("expected 415, got %d body=%s", resp.Code, resp.Body.String())
			}
			assertJSONError(t, resp, "unsupported_media_type")

			ok, msg, err := model.ValiClient("svc-no-form-rotate", "https://app.example.com/cb", oldSecret)
			if err != nil || !ok {
				t.Fatalf("rejected request changed the secret: ok=%v msg=%q err=%v", ok, msg, err)
			}
		})
	}
}

func TestAdminUpdateAndDeleteClient(t *testing.T) {
	env := setupAdminTest(t)
	if resp := adminRequest(t, env, http.MethodPost, "/x/admin/clients", createClientBody("svc-del"), env.user); resp.Code != http.StatusCreated {
		t.Fatalf("create failed: %d body=%s", resp.Code, resp.Body.String())
	}

	resp := adminRequest(t, env, http.MethodPatch, "/x/admin/clients/svc-del",
		`{"name":"Renamed","redirect_uris":["https://renamed.example.com/cb"]}`, env.user)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	if name, _ := decodeJSONMap(t, resp)["name"].(string); name != "Renamed" {
		t.Fatalf("expected the rename to be reflected, got %s", resp.Body.String())
	}
	// The replaced redirect URI must stop matching.
	if ok, _, _ := model.ValiClientWithUrl("svc-del", "https://app.example.com/cb"); ok {
		t.Fatal("the replaced redirect URI still validates")
	}

	if resp := adminRequest(t, env, http.MethodDelete, "/x/admin/clients/svc-del", "", env.user); resp.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d body=%s", resp.Code, resp.Body.String())
	}
	if ok, _, _ := model.ValiClientWithUrl("svc-del", "https://renamed.example.com/cb"); ok {
		t.Fatal("a deleted client still validates")
	}
	if exists, err := model.ClientExists("svc-del"); err != nil || exists {
		t.Fatalf("a deleted client is still visible to the token endpoint: exists=%v err=%v", exists, err)
	}
	if resp := adminRequest(t, env, http.MethodGet, "/x/admin/clients/svc-del", "", env.user); resp.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after deletion, got %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestAdminClientNotFound(t *testing.T) {
	env := setupAdminTest(t)
	for _, tc := range []struct{ method, target, body string }{
		{http.MethodGet, "/x/admin/clients/nope", ""},
		{http.MethodPatch, "/x/admin/clients/nope", `{"name":"X"}`},
		{http.MethodPost, "/x/admin/clients/nope/secret", ""},
		{http.MethodDelete, "/x/admin/clients/nope", ""},
	} {
		resp := adminRequest(t, env, tc.method, tc.target, tc.body, env.user)
		if resp.Code != http.StatusNotFound {
			t.Fatalf("%s %s: expected 404, got %d body=%s", tc.method, tc.target, resp.Code, resp.Body.String())
		}
	}
}
