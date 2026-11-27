package auth

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/management/oauth"
	permission "github.com/Asutorufa/yuhaiin/pkg/management/permission"
)

const testIssuer = "https://yuhaiin.test"

// oauthTest is a management gate with the Authorization Server enabled, a
// management API resource and an OAuth-only resource standing in for MCP.
type oauthTest struct {
	t      *testing.T
	store  *Store
	as     *AuthorizationServer
	server *Server
	http   *httptest.Server
	admin  User
	calls  map[string]int
	mu     sync.Mutex
}

func testOnlyResource() oauth.Resource {
	return oauth.Resource{ID: "mcp", Name: "MCP", Path: "/mcp", Prefixes: []string{"/mcp"}, Scopes: []Permission{MCPConnect, NodesRead, NodesWrite}, Required: MCPConnect}
}

func newOAuthTest(t *testing.T) *oauthTest {
	t.Helper()
	s := testStore(t)
	registry := &oauth.Registry{}
	for _, r := range []oauth.Resource{ManagementAPIResource(), testOnlyResource()} {
		if err := registry.Register(r); err != nil {
			t.Fatal(err)
		}
	}
	o := &oauthTest{t: t, store: s, as: newAuthorizationServer(s, registry), calls: map[string]int{}}
	o.as.limiter = newRateLimiter(1<<20, 1<<20)
	o.admin = testUser(t, s, "admin", Admin)
	permissions := map[string]Permission{
		"POST /api/v2/rpc/nodes.get": NodesRead, "POST /api/v2/rpc/node.put": NodesWrite, "POST /api/v2/rpc/settings.get": SettingsRead,
		"POST /mcp": MCPConnect,
	}
	mux := http.NewServeMux()
	for pattern := range permissions {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			p, _ := FromContext(r.Context())
			if !permission.Allowed(r.Context(), permissions[pattern]) {
				t.Errorf("handler for %s ran without its permission", pattern)
			}
			o.mu.Lock()
			o.calls[pattern]++
			o.mu.Unlock()
			_ = json.MarshalWrite(w, p)
		})
	}
	mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ui") })
	o.server = &Server{Store: s, Permissions: permissions, Authorization: o.as, AcceptOrigin: func(origin string, _ *http.Request) bool { return origin == "https://ui.test" }}
	o.server.Register(mux)
	o.http = httptest.NewServer(o.server.Wrap(mux))
	t.Cleanup(o.http.Close)
	o.settings(func(s *OAuthServerSettings) { s.Enabled, s.Issuer = true, testIssuer })
	return o
}

func (o *oauthTest) settings(change func(*OAuthServerSettings)) {
	o.t.Helper()
	current, err := o.as.Settings(o.t.Context())
	if err != nil {
		o.t.Fatal(err)
	}
	change(&current)
	if _, err := o.as.SaveSettings(o.t.Context(), principal(o.admin), current); err != nil {
		o.t.Fatal(err)
	}
}

func (o *oauthTest) client(kind string, resources []string, scopes []Permission) IssuedOAuthClient {
	o.t.Helper()
	request := OAuthClientRequest{Name: "Test " + kind, Type: kind, RedirectURIs: []string{"https://client.test/callback", "http://127.0.0.1/callback"}, Resources: resources, Scopes: scopes}
	c, err := o.as.CreateClient(o.t.Context(), principal(o.admin), request)
	if err != nil {
		o.t.Fatal(err)
	}
	return c
}

const testVerifier = "test-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"

func authorizeValues(client, resource, scope string) url.Values {
	v := url.Values{"response_type": {"code"}, "client_id": {client}, "redirect_uri": {"https://client.test/callback"}, "state": {"opaque-state"},
		"code_challenge": {oauth.S256Challenge(testVerifier)}, "code_challenge_method": {"S256"}, "scope": {scope}}
	if resource != "" {
		v.Set("resource", testIssuer+resource)
	}
	return v
}

// code runs an authorization request and the user's approval.
func (o *oauthTest) code(actor User, values url.Values, selected []Permission) string {
	o.t.Helper()
	request, err := o.as.StartAuthorization(o.t.Context(), values)
	if err != nil {
		o.t.Fatal(err)
	}
	if selected == nil {
		selected = request.Scopes
	}
	redirect, err := o.as.Decide(o.t.Context(), principal(actor), request.ID, true, selected)
	if err != nil {
		o.t.Fatal(err)
	}
	u, _ := url.Parse(redirect)
	if u.Query().Get("state") != "opaque-state" || u.Query().Get("iss") != testIssuer || !strings.HasPrefix(redirect, "https://client.test/callback?") {
		o.t.Fatalf("authorization response %s", redirect)
	}
	return u.Query().Get("code")
}

func (o *oauthTest) post(path string, form url.Values, basic [2]string) (int, map[string]any) {
	o.t.Helper()
	request, _ := http.NewRequest(http.MethodPost, o.http.URL+path, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic[0] != "" {
		request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(basic[0])+":"+url.QueryEscape(basic[1]))))
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		o.t.Fatal(err)
	}
	defer response.Body.Close()
	out := map[string]any{}
	_ = json.UnmarshalRead(response.Body, &out)
	return response.StatusCode, out
}

func (o *oauthTest) exchange(clientID, code string, extra url.Values, basic [2]string) (int, map[string]any) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://client.test/callback"}, "code_verifier": {testVerifier}}
	if basic[0] == "" {
		form.Set("client_id", clientID)
	}
	maps.Copy(form, extra)
	return o.post(oauthTokenPath, form, basic)
}

func (o *oauthTest) refresh(clientID, token string, extra url.Values) (int, map[string]any) {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}, "client_id": {clientID}}
	maps.Copy(form, extra)
	return o.post(oauthTokenPath, form, [2]string{})
}

func (o *oauthTest) call(method, path, authorization string) (int, http.Header) {
	o.t.Helper()
	request, _ := http.NewRequest(method, o.http.URL+path, nil)
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		o.t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	return response.StatusCode, response.Header
}

func (o *oauthTest) tokens(user User, client, resource, scope string) (string, string) {
	o.t.Helper()
	status, body := o.exchange(client, o.code(user, authorizeValues(client, resource, scope), nil), nil, [2]string{})
	if status != http.StatusOK {
		o.t.Fatalf("token exchange = %d %v", status, body)
	}
	return body["access_token"].(string), body["refresh_token"].(string)
}

func (o *oauthTest) events(event string) int {
	var n int
	if err := o.store.db.QueryRowContext(o.t.Context(), `SELECT count(*) FROM management_security_events WHERE event=?`, event).Scan(&n); err != nil {
		o.t.Fatal(err)
	}
	return n
}

func TestOAuthAuthorizationCodeFlowAndResourceBinding(t *testing.T) {
	o := newOAuthTest(t)
	client := o.client("public", nil, nil)

	// Discovery documents.
	response, err := http.Get(o.http.URL + oauthMetadataPath)
	if err != nil {
		t.Fatal(err)
	}
	var metadata oauth.AuthorizationServerMetadata
	if err := json.UnmarshalRead(response.Body, &metadata); err != nil || response.StatusCode != 200 {
		t.Fatal(response.StatusCode, err)
	}
	response.Body.Close()
	if metadata.Issuer != testIssuer || metadata.TokenEndpoint != testIssuer+"/oauth/token" || !slices.Equal(metadata.CodeChallengeMethodsSupported, []string{"S256"}) ||
		!slices.Equal(metadata.GrantTypesSupported, []string{"authorization_code", "refresh_token"}) || metadata.RegistrationEndpoint == "" || slices.Contains(metadata.ScopesSupported, string(UsersManage)) {
		t.Fatalf("metadata = %+v", metadata)
	}
	response, _ = http.Get(o.http.URL + "/.well-known/oauth-protected-resource/mcp")
	var prm oauth.ProtectedResourceMetadata
	_ = json.UnmarshalRead(response.Body, &prm)
	response.Body.Close()
	if prm.Resource != testIssuer+"/mcp" || !slices.Equal(prm.AuthorizationServers, []string{testIssuer}) {
		t.Fatalf("protected resource metadata = %+v", prm)
	}

	// The authorization endpoint sends the browser to the consent page.
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err = noRedirect.Get(o.http.URL + oauthAuthorizePath + "?" + authorizeValues(client.ID, "/api", "nodes:read").Encode())
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther || !strings.HasPrefix(response.Header.Get("Location"), testIssuer+"/#/oauth/consent/") || response.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("authorize = %d %s", response.StatusCode, response.Header.Get("Location"))
	}

	access, refresh := o.tokens(o.admin, client.ID, "/api", "nodes:read")
	bearer := "Bearer " + access
	if status, _ := o.call("POST", "/api/v2/rpc/nodes.get", bearer); status != 200 {
		t.Fatalf("granted scope = %d", status)
	}
	status, header := o.call("POST", "/api/v2/rpc/node.put", bearer)
	if status != 403 || !strings.Contains(header.Get("WWW-Authenticate"), `error="insufficient_scope"`) || !strings.Contains(header.Get("WWW-Authenticate"), `scope="nodes:write"`) {
		t.Fatalf("missing scope = %d %q", status, header.Get("WWW-Authenticate"))
	}
	if o.events("oauth.permission.denied") != 1 {
		t.Fatal("OAuth permission denial was not audited")
	}
	// An API token must never be usable at another resource.
	if status, header := o.call("POST", "/mcp", bearer); status != 401 || !strings.Contains(header.Get("WWW-Authenticate"), `resource_metadata="https://yuhaiin.test/.well-known/oauth-protected-resource/mcp"`) {
		t.Fatalf("audience = %d %q", status, header.Get("WWW-Authenticate"))
	}
	if o.events("oauth.authentication.failed") == 0 {
		t.Fatal("audience mismatch was not audited")
	}
	// Refresh rotates; the old refresh token is then a reuse that revokes the family.
	status, body := o.refresh(client.ID, refresh, nil)
	if status != 200 || body["refresh_token"] == refresh {
		t.Fatalf("refresh = %d %v", status, body)
	}
	rotatedAccess := body["access_token"].(string)
	if status, _ := o.call("POST", "/api/v2/rpc/nodes.get", "Bearer "+rotatedAccess); status != 200 {
		t.Fatal("refreshed access token rejected")
	}
	if status, body := o.refresh(client.ID, refresh, nil); status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("reuse = %d %v", status, body)
	}
	if o.events("oauth.refresh.reuse_detected") != 1 {
		t.Fatal("reuse was not audited")
	}
	for _, token := range []string{access, rotatedAccess} {
		if status, _ := o.call("POST", "/api/v2/rpc/nodes.get", "Bearer "+token); status != 401 {
			t.Fatal("token family survived refresh token reuse")
		}
	}
	if status, _ := o.refresh(client.ID, body["refresh_token"].(string), nil); status == 200 {
		t.Fatal("newest refresh token survived reuse detection")
	}

	// An MCP token works only at MCP.
	mcpAccess, _ := o.tokens(o.admin, client.ID, "/mcp", "")
	if status, _ := o.call("POST", "/mcp", "Bearer "+mcpAccess); status != 200 {
		t.Fatal("MCP token rejected at MCP")
	}
	if status, _ := o.call("POST", "/api/v2/rpc/nodes.get", "Bearer "+mcpAccess); status != 401 {
		t.Fatal("MCP token accepted by the management API")
	}
	for _, event := range []string{"oauth.authorization.approved", "oauth.code.issued", "oauth.code.consumed", "oauth.token.issued", "oauth.token.refreshed", "oauth.grant.revoked", "oauth.client.created"} {
		if o.events(event) == 0 {
			t.Errorf("missing audit event %s", event)
		}
	}
	var leaked int
	_ = o.store.db.QueryRowContext(t.Context(), `SELECT count(*) FROM management_security_events WHERE instr(changes_json,?)>0 OR instr(changes_json,?)>0 OR instr(changes_json,?)>0`, access, refresh, testVerifier).Scan(&leaked)
	if leaked != 0 {
		t.Fatal("audit contains a secret")
	}
}

func TestOAuthAuthorizationRequestValidation(t *testing.T) {
	o := newOAuthTest(t)
	client := o.client("public", nil, []Permission{NodesRead, MCPConnect})
	set := func(key, value string) url.Values {
		v := authorizeValues(client.ID, "/api", "nodes:read")
		if value == "" {
			v.Del(key)
		} else {
			v.Set(key, value)
		}
		return v
	}
	for _, tt := range []struct {
		name     string
		values   url.Values
		redirect bool
		code     string
	}{
		{"unknown client", set("client_id", "nope"), false, "invalid_client"},
		{"unregistered redirect", set("redirect_uri", "https://evil.test/callback"), false, "invalid_request"},
		{"redirect prefix", set("redirect_uri", "https://client.test/callback/extra"), false, "invalid_request"},
		{"repeated parameter", func() url.Values { v := set("scope", "nodes:read"); v.Add("scope", "nodes:read"); return v }(), false, "invalid_request"},
		{"implicit", set("response_type", "token"), true, "unsupported_response_type"},
		{"missing pkce", set("code_challenge", ""), true, "invalid_request"},
		{"plain pkce", set("code_challenge_method", "plain"), true, "invalid_request"},
		{"unknown resource", set("resource", "https://other.test/api"), true, "invalid_target"},
		{"missing resource", set("resource", ""), true, "invalid_target"},
		{"scope beyond client", set("scope", "nodes:write"), true, "invalid_scope"},
		{"non-delegable scope", set("scope", "users:manage"), true, "invalid_scope"},
		{"oversized state", set("state", strings.Repeat("s", maxStateLength+1)), false, "invalid_request"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := o.as.StartAuthorization(t.Context(), tt.values)
			var redirect *redirectError
			var plain *oauth.Error
			switch {
			case tt.redirect && (!asRedirect(err, &redirect) || redirect.err.Code != tt.code):
				t.Fatalf("err = %v, want redirect %s", err, tt.code)
			case tt.redirect:
				u, _ := url.Parse(redirect.location())
				if u.Host != "client.test" || u.Query().Get("state") != "opaque-state" || u.Query().Get("error") != tt.code || u.Query().Get("iss") != testIssuer {
					t.Fatalf("redirect = %s", redirect.location())
				}
			case !asOAuth(err, &plain) || asRedirect(err, &redirect) || plain.Code != tt.code:
				t.Fatalf("err = %v, want non-redirect %s", err, tt.code)
			}
		})
	}
	// Loopback redirects may use any port (RFC 8252); other hosts may not.
	v := authorizeValues(client.ID, "/api", "nodes:read")
	v.Set("redirect_uri", "http://127.0.0.1:53682/callback")
	if _, err := o.as.StartAuthorization(t.Context(), v); err != nil {
		t.Fatal("loopback port variation rejected:", err)
	}
	// The required MCP scope is always part of an MCP request.
	request, err := o.as.StartAuthorization(t.Context(), authorizeValues(client.ID, "/mcp", "nodes:read"))
	if err != nil || !slices.Contains(request.Scopes, MCPConnect) {
		t.Fatal(request.Scopes, err)
	}
	// A disabled resource cannot be requested.
	o.settings(func(s *OAuthServerSettings) { s.DisabledResources = []string{"mcp"} })
	if _, err := o.as.StartAuthorization(t.Context(), authorizeValues(client.ID, "/mcp", "")); err == nil {
		t.Fatal("disabled resource accepted")
	}
}

func asRedirect(err error, out **redirectError) bool {
	r, ok := err.(*redirectError)
	*out = r
	return ok
}

func asOAuth(err error, out **oauth.Error) bool {
	r, ok := err.(*oauth.Error)
	*out = r
	return ok
}

func TestOAuthAuthorizationAcceptsLongState(t *testing.T) {
	o := newOAuthTest(t)
	client := o.client("public", nil, nil)
	// Google's account-linking state is about 1.5 KB of base64url.
	state := strings.Repeat("AMskz5qUvVnKjImA46DaNMj_mYASyACuDOT20nsa", 40)
	values := authorizeValues(client.ID, "/mcp", "mcp:connect")
	values.Set("state", state)
	request, err := o.as.StartAuthorization(t.Context(), values)
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := o.as.Decide(t.Context(), principal(o.admin), request.ID, true, request.Scopes)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(redirect)
	if u.Query().Get("state") != state || u.Query().Get("code") == "" {
		t.Fatalf("authorization response %s", redirect)
	}
}

func TestOAuthConsentNeverExceedsUserPermissions(t *testing.T) {
	o := newOAuthTest(t)
	reader := testUser(t, o.store, "reader", ReadOnly)
	client := o.client("public", nil, nil)
	request, err := o.as.StartAuthorization(t.Context(), authorizeValues(client.ID, "/api", "nodes:read nodes:write"))
	if err != nil {
		t.Fatal(err)
	}
	details, err := o.as.Authorization(t.Context(), principal(reader), request.ID)
	if err != nil || len(details.Scopes) != 2 || !details.Scopes[0].Available || details.Scopes[1].Available || details.Scopes[1].Access != "write" || details.RedirectOrigin != "https://client.test" {
		t.Fatalf("consent = %+v %v", details, err)
	}
	if _, err := o.as.Decide(t.Context(), principal(reader), request.ID, true, []Permission{NodesRead, SecretsRead}); err == nil {
		t.Fatal("selection beyond the request accepted")
	}
	// A pending request is single use.
	if _, err := o.as.Decide(t.Context(), principal(reader), request.ID, true, []Permission{NodesRead}); err == nil {
		t.Fatal("pending request reused")
	}
	access, _ := o.tokens(reader, client.ID, "/api", "nodes:read nodes:write")
	if status, _ := o.call("POST", "/api/v2/rpc/node.put", "Bearer "+access); status != 403 {
		t.Fatal("token exceeded the user's permissions")
	}
	if status, _ := o.call("POST", "/api/v2/rpc/nodes.get", "Bearer "+access); status != 200 {
		t.Fatal("granted read rejected")
	}
	// Denial returns access_denied to the client.
	request, _ = o.as.StartAuthorization(t.Context(), authorizeValues(client.ID, "/api", "nodes:read"))
	redirect, err := o.as.Decide(t.Context(), principal(reader), request.ID, false, nil)
	if err != nil || !strings.Contains(redirect, "error=access_denied") || o.events("oauth.authorization.denied") != 1 {
		t.Fatal(redirect, err)
	}
}

func TestOAuthCodeExchangeValidation(t *testing.T) {
	o := newOAuthTest(t)
	public := o.client("public", nil, nil)
	other := o.client("public", nil, nil)
	confidential := o.client("confidential", nil, nil)
	if confidential.Secret == "" || !strings.HasPrefix(confidential.Secret, oauth.ClientSecretPrefix) {
		t.Fatal("confidential client has no secret")
	}
	var stored []byte
	_ = o.store.db.QueryRowContext(t.Context(), `SELECT secret_hash FROM management_oauth_clients WHERE id=?`, confidential.ID).Scan(&stored)
	if string(stored) == confidential.Secret || len(stored) != 32 {
		t.Fatal("client secret stored in plaintext")
	}
	values := func() url.Values { return authorizeValues(public.ID, "/api", "nodes:read") }
	for _, tt := range []struct {
		name  string
		extra url.Values
		as    string
		want  string
	}{
		{"wrong verifier", url.Values{"code_verifier": {strings.Repeat("x", 50)}}, public.ID, "invalid_grant"},
		{"short verifier", url.Values{"code_verifier": {"short"}}, public.ID, "invalid_grant"},
		{"other client", nil, other.ID, "invalid_grant"},
		{"redirect mismatch", url.Values{"redirect_uri": {"http://127.0.0.1/callback"}}, public.ID, "invalid_grant"},
		{"redirect omitted", url.Values{"redirect_uri": {""}}, public.ID, "invalid_grant"},
		{"resource mismatch", url.Values{"resource": {testIssuer + "/mcp"}}, public.ID, "invalid_target"},
		{"unsupported grant", url.Values{"grant_type": {"password"}}, public.ID, "unsupported_grant_type"},
		{"unknown client", nil, "missing", "invalid_client"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			code := o.code(o.admin, values(), nil)
			status, body := o.exchange(tt.as, code, tt.extra, [2]string{})
			if status < 400 || body["error"] != tt.want {
				t.Fatalf("status %d body %v, want %s", status, body, tt.want)
			}
		})
	}
	t.Run("expired", func(t *testing.T) {
		code := o.code(o.admin, values(), nil)
		_, _ = o.store.db.ExecContext(t.Context(), `UPDATE management_oauth_codes SET expires_at=1 WHERE verifier=?`, oauth.Hash(code))
		if status, body := o.exchange(public.ID, code, nil, [2]string{}); status != 400 || body["error"] != "invalid_grant" {
			t.Fatal(status, body)
		}
	})
	t.Run("single use and replay revocation", func(t *testing.T) {
		code := o.code(o.admin, values(), nil)
		status, body := o.exchange(public.ID, code, nil, [2]string{})
		if status != 200 || body["token_type"] != "Bearer" || body["scope"] != "nodes:read" || body["expires_in"] != float64(900) {
			t.Fatal(status, body)
		}
		if status, _ := o.exchange(public.ID, code, nil, [2]string{}); status != 400 {
			t.Fatal("code reused")
		}
		if status, _ := o.call("POST", "/api/v2/rpc/nodes.get", "Bearer "+body["access_token"].(string)); status != 401 {
			t.Fatal("tokens from a replayed code remain valid")
		}
	})
	t.Run("confidential client", func(t *testing.T) {
		code := o.code(o.admin, authorizeValues(confidential.ID, "/api", "nodes:read"), nil)
		if status, body := o.exchange(confidential.ID, code, nil, [2]string{}); status != 401 || body["error"] != "invalid_client" {
			t.Fatal("confidential client without a secret", status, body)
		}
		if status, _ := o.exchange(confidential.ID, code, nil, [2]string{confidential.ID, oauth.NewSecret(oauth.ClientSecretPrefix)}); status != 401 {
			t.Fatal("wrong client secret accepted")
		}
		if status, body := o.exchange(confidential.ID, code, url.Values{"client_secret": {confidential.Secret}, "client_id": {confidential.ID}}, [2]string{}); status != 401 {
			t.Fatal("client_secret_post accepted for a client_secret_basic client", body)
		}
		if status, body := o.exchange(confidential.ID, code, nil, [2]string{confidential.ID, confidential.Secret}); status != 200 {
			t.Fatal(status, body)
		}
	})
	t.Run("query parameters rejected", func(t *testing.T) {
		if status, _ := o.post(oauthTokenPath+"?grant_type=authorization_code", url.Values{"client_id": {public.ID}}, [2]string{}); status != 400 {
			t.Fatal("token endpoint accepted query parameters")
		}
	})
}

func TestOAuthTokenLifecycleAndRevocation(t *testing.T) {
	o := newOAuthTest(t)
	client := o.client("public", nil, nil)
	active := func(token string) bool {
		status, _ := o.call("POST", "/api/v2/rpc/nodes.get", "Bearer "+token)
		return status == 200
	}
	t.Run("access token expiry", func(t *testing.T) {
		access, _ := o.tokens(o.admin, client.ID, "/api", "nodes:read")
		_, _ = o.store.db.ExecContext(t.Context(), `UPDATE management_credentials SET expires_at=1 WHERE verifier=?`, oauth.Hash(access))
		if active(access) {
			t.Fatal("expired access token accepted")
		}
	})
	t.Run("revocation endpoint", func(t *testing.T) {
		access, refresh := o.tokens(o.admin, client.ID, "/api", "nodes:read")
		if status, _ := o.post(oauthRevokePath, url.Values{"token": {access}, "client_id": {client.ID}}, [2]string{}); status != 200 || active(access) {
			t.Fatal("access token revocation failed")
		}
		if status, _ := o.refresh(client.ID, refresh, nil); status != 200 {
			t.Fatal("revoking an access token revoked its refresh token")
		}
		access, refresh = o.tokens(o.admin, client.ID, "/api", "nodes:read")
		if status, _ := o.post(oauthRevokePath, url.Values{"token": {refresh}, "client_id": {client.ID}}, [2]string{}); status != 200 || active(access) {
			t.Fatal("refresh token revocation did not revoke the grant")
		}
		// Unknown tokens and other clients' tokens are ignored with 200.
		other := o.client("public", nil, nil)
		access, _ = o.tokens(o.admin, client.ID, "/api", "nodes:read")
		if status, _ := o.post(oauthRevokePath, url.Values{"token": {access}, "client_id": {other.ID}}, [2]string{}); status != 200 || !active(access) {
			t.Fatal("another client revoked a token")
		}
		if status, _ := o.post(oauthRevokePath, url.Values{"token": {"garbage"}, "client_id": {client.ID}}, [2]string{}); status != 200 {
			t.Fatal("unknown token revocation failed")
		}
	})
	t.Run("grant revocation", func(t *testing.T) {
		access, refresh := o.tokens(o.admin, client.ID, "/api", "nodes:read")
		var grant string
		_ = o.store.db.QueryRowContext(t.Context(), `SELECT grant_id FROM management_credentials WHERE verifier=?`, oauth.Hash(access)).Scan(&grant)
		other := testUser(t, o.store, "not-owner", ReadOnly)
		if err := o.as.RevokeGrant(t.Context(), principal(other), grant); err != ErrForbidden {
			t.Fatal("another user revoked a grant", err)
		}
		if err := o.as.RevokeGrant(t.Context(), principal(o.admin), grant); err != nil {
			t.Fatal(err)
		}
		if active(access) {
			t.Fatal("grant revocation left the access token valid")
		}
		if status, _ := o.refresh(client.ID, refresh, nil); status == 200 {
			t.Fatal("grant revocation left the refresh token valid")
		}
	})
	t.Run("user disable", func(t *testing.T) {
		u := testUser(t, o.store, "disable-me", Admin)
		access, refresh := o.tokens(u, client.ID, "/api", "nodes:read")
		if err := o.store.UpdateUser(t.Context(), o.admin.ID, u.ID, u.Login, u.Role, true); err != nil {
			t.Fatal(err)
		}
		if err := o.store.UpdateUser(t.Context(), o.admin.ID, u.ID, u.Login, u.Role, false); err != nil {
			t.Fatal(err)
		}
		if active(access) {
			t.Fatal("re-enabling resurrected an OAuth token")
		}
		if status, _ := o.refresh(client.ID, refresh, nil); status == 200 {
			t.Fatal("re-enabling resurrected a refresh token")
		}
	})
	t.Run("role change", func(t *testing.T) {
		u := testUser(t, o.store, "demote-me", Admin)
		read, _ := o.tokens(u, client.ID, "/api", "nodes:read")
		write, refresh := o.tokens(u, client.ID, "/api", "nodes:write")
		if err := o.store.UpdateUser(t.Context(), o.admin.ID, u.ID, u.Login, ReadOnly, false); err != nil {
			t.Fatal(err)
		}
		if !active(read) {
			t.Fatal("a grant still backed by the new role was revoked")
		}
		if status, _ := o.call("POST", "/api/v2/rpc/node.put", "Bearer "+write); status != 401 {
			t.Fatal("grant beyond the new role survived")
		}
		// Promotion does not restore the revoked grant.
		_ = o.store.UpdateUser(t.Context(), o.admin.ID, u.ID, u.Login, Admin, false)
		if status, _ := o.refresh(client.ID, refresh, nil); status == 200 {
			t.Fatal("refresh restored a revoked grant after promotion")
		}
	})
	t.Run("custom role permission change", func(t *testing.T) {
		u := testUser(t, o.store, "custom", NoManagement)
		role, err := o.store.SaveRole(t.Context(), principal(o.admin), Role{Name: "Operators", Permissions: []Permission{NodesRead}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := o.store.AssignRoles(t.Context(), principal(o.admin), u.ID, 0, []string{role.ID}); err != nil {
			t.Fatal(err)
		}
		access, _ := o.tokens(u, client.ID, "/api", "nodes:read")
		if !active(access) {
			t.Fatal("custom role grant rejected")
		}
		role.Permissions = []Permission{SettingsRead}
		if _, err := o.store.SaveRole(t.Context(), principal(o.admin), role); err != nil {
			t.Fatal(err)
		}
		if active(access) {
			t.Fatal("permission removed from a custom role but the token still works")
		}
	})
	t.Run("credential generation change", func(t *testing.T) {
		u := testUser(t, o.store, "reset-me", Admin)
		access, refresh := o.tokens(u, client.ID, "/api", "nodes:read")
		if _, err := o.store.ResetEnrollment(t.Context(), o.admin.ID, u.ID); err != nil {
			t.Fatal(err)
		}
		_, _ = o.store.db.ExecContext(t.Context(), `UPDATE management_users SET credential='again' WHERE id=?`, u.ID)
		if active(access) {
			t.Fatal("credential reset left the token valid")
		}
		if status, _ := o.refresh(client.ID, refresh, nil); status == 200 {
			t.Fatal("credential reset left the refresh token valid")
		}
	})
	t.Run("client disable", func(t *testing.T) {
		c := o.client("public", nil, nil)
		access, refresh := o.tokens(o.admin, c.ID, "/api", "nodes:read")
		if _, err := o.as.UpdateClient(t.Context(), principal(o.admin), c.ID, OAuthClientRequest{Name: c.Name, RedirectURIs: c.RedirectURIs, Disabled: true}); err != nil {
			t.Fatal(err)
		}
		if active(access) {
			t.Fatal("disabled client's token accepted")
		}
		if status, body := o.refresh(c.ID, refresh, nil); status != 401 || body["error"] != "invalid_client" {
			t.Fatal("disabled client refreshed", status, body)
		}
		if o.events("oauth.client.disabled") != 1 {
			t.Fatal("client disable not audited")
		}
	})
	t.Run("server and resource disable", func(t *testing.T) {
		access, _ := o.tokens(o.admin, client.ID, "/api", "nodes:read")
		o.settings(func(s *OAuthServerSettings) { s.DisabledResources = []string{"api"} })
		if active(access) {
			t.Fatal("token for a disabled resource accepted")
		}
		o.settings(func(s *OAuthServerSettings) { s.DisabledResources = nil; s.Enabled = false })
		if active(access) {
			t.Fatal("token accepted while the server is disabled")
		}
		if status, _ := o.call("GET", oauthMetadataPath, ""); status != 404 {
			t.Fatal("metadata served while disabled")
		}
		if status, _ := o.call("POST", "/mcp", ""); status != 404 {
			t.Fatal("OAuth-only resource served while disabled")
		}
		o.settings(func(s *OAuthServerSettings) { s.Enabled = true })
		if !active(access) {
			t.Fatal("re-enabling the server did not restore a valid token")
		}
		o.settings(func(s *OAuthServerSettings) { s.Issuer = "https://moved.test" })
		if active(access) {
			t.Fatal("token for the previous issuer's resource accepted")
		}
	})
}

func TestOAuthCredentialTypesStaySeparate(t *testing.T) {
	o := newOAuthTest(t)
	client := o.client("public", nil, nil)
	apiToken, err := o.store.IssueToken(t.Context(), principal(o.admin), o.admin.ID, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	access, refresh := o.tokens(o.admin, client.ID, "/mcp", "")
	for _, tt := range []struct {
		name, path, authorization string
		want                      int
	}{
		{"api token at api", "/api/v2/rpc/nodes.get", "Bearer " + apiToken.Secret, 200},
		{"api token at mcp", "/mcp", "Bearer " + apiToken.Secret, 401},
		{"oauth access in session header", "/api/v2/rpc/nodes.get", "Session " + access, 401},
		{"refresh token as bearer", "/mcp", "Bearer " + refresh, 401},
		{"oauth-looking api token", "/api/v2/rpc/nodes.get", "Bearer " + oauth.AccessTokenPrefix + apiToken.Secret[3:], 401},
		{"no credential at mcp", "/mcp", "", 401},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if status, _ := o.call("POST", tt.path, tt.authorization); status != tt.want {
				t.Fatalf("status %d, want %d", status, tt.want)
			}
		})
	}
	if p, err := o.store.Authenticate(t.Context(), access, "token"); err == nil {
		t.Fatal("OAuth access token authenticated as an API token", p)
	}
}

// Sessions, API tokens and OAuth tokens with the same permissions reach the
// same authorization decision on the same routes, through the same gate.
func TestOAuthHTTPAPIAuthorizationParity(t *testing.T) {
	o := newOAuthTest(t)
	reader := testUser(t, o.store, "parity", ReadOnly)
	client := o.client("public", []string{"api"}, nil)
	tx, _ := o.store.db.BeginTx(t.Context(), nil)
	session, err := issueCredential(t.Context(), tx, reader.ID, "session", nil, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	_ = tx.Commit()
	apiToken, _ := o.store.IssueToken(t.Context(), principal(o.admin), reader.ID, []Permission{NodesRead, SettingsRead}, 0)
	access, _ := o.tokens(reader, client.ID, "/api", "nodes:read settings:read")
	routes := map[string]int{"/api/v2/rpc/nodes.get": 200, "/api/v2/rpc/settings.get": 200, "/api/v2/rpc/node.put": 403}
	for name, authorization := range map[string]string{"session": "Session " + session.Secret, "token": "Bearer " + apiToken.Secret, "oauth": "Bearer " + access} {
		for path, want := range routes {
			if status, _ := o.call("POST", path, authorization); status != want {
				t.Errorf("%s %s = %d, want %d", name, path, status, want)
			}
		}
	}
	var methods []string
	rows, _ := o.store.db.QueryContext(t.Context(), `SELECT DISTINCT auth_method FROM management_security_events WHERE event IN ('permission.denied','oauth.permission.denied') ORDER BY auth_method`)
	for rows.Next() {
		var m string
		_ = rows.Scan(&m)
		methods = append(methods, m)
	}
	rows.Close()
	if !slices.Contains(methods, "oauth") || !slices.Contains(methods, "token") {
		t.Fatalf("denials audited for %v", methods)
	}
}

func TestOAuthOpenCORSAndOriginPolicy(t *testing.T) {
	o := newOAuthTest(t)
	request, _ := http.NewRequest(http.MethodOptions, o.http.URL+oauthTokenPath, nil)
	request.Header.Set("Origin", "https://inspector.test")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 204 || response.Header.Get("Access-Control-Allow-Origin") != "*" || response.Header.Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("token endpoint CORS", response.StatusCode, response.Header)
	}
	request, _ = http.NewRequest(http.MethodPost, o.http.URL+"/mcp", nil)
	request.Header.Set("Origin", "https://evil.test")
	response, _ = http.DefaultClient.Do(request)
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("untrusted origin reached MCP", response.StatusCode)
	}
	// Consent endpoints require a session, not an OAuth token.
	client := o.client("public", nil, nil)
	access, _ := o.tokens(o.admin, client.ID, "/api", "identity:read")
	if status, _ := o.call("GET", oauthServerAPI+"/grants", "Bearer "+access); status != 403 {
		t.Fatal("OAuth token managed grants", status)
	}
}

func TestOAuthDynamicClientRegistration(t *testing.T) {
	o := newOAuthTest(t)
	register := func(body string) (int, map[string]any) {
		response, err := http.Post(o.http.URL+oauthRegisterPath, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		out := map[string]any{}
		_ = json.UnmarshalRead(response.Body, &out)
		return response.StatusCode, out
	}
	status, body := register(`{"client_name":"Claude","redirect_uris":["http://localhost:3334/callback"],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"response_types":["code"]}`)
	if status != 201 || body["client_id"] == "" || body["client_secret"] != nil {
		t.Fatal(status, body)
	}
	status, body = register(`{"client_name":"Server","redirect_uris":["https://app.test/cb"],"token_endpoint_auth_method":"client_secret_basic"}`)
	if status != 201 || !strings.HasPrefix(body["client_secret"].(string), oauth.ClientSecretPrefix) {
		t.Fatal(status, body)
	}
	for _, bad := range []string{
		`{"redirect_uris":["http://attacker.test/cb"]}`,
		`{"redirect_uris":["https://*.test/cb"]}`,
		`{"redirect_uris":["javascript:alert(1)"]}`,
		`{"redirect_uris":["https://app.test/cb#x"]}`,
		`{"redirect_uris":["https://app.test/cb"],"grant_types":["password"]}`,
		`{"redirect_uris":["https://app.test/cb"],"grant_types":["implicit"]}`,
		`{"redirect_uris":["https://app.test/cb"],"scope":"users:manage"}`,
		`{"redirect_uris":["myapp:/cb"],"token_endpoint_auth_method":"client_secret_basic"}`,
		`not json`,
	} {
		if status, body := register(bad); status != 400 {
			t.Errorf("%s registered: %d %v", bad, status, body)
		}
	}
	o.settings(func(s *OAuthServerSettings) { s.DynamicRegistration = false })
	if status, _ := register(`{"redirect_uris":["http://127.0.0.1/cb"]}`); status != 403 {
		t.Fatal("registration allowed while disabled")
	}
	clients, _ := o.as.Clients(t.Context())
	if len(clients) != 2 || clients[0].Registration != "dynamic" {
		t.Fatalf("clients = %+v", clients)
	}
}

func TestOAuthSettingsValidation(t *testing.T) {
	o := newOAuthTest(t)
	current, _ := o.as.Settings(t.Context())
	for _, mutate := range []func(*OAuthServerSettings){
		func(s *OAuthServerSettings) { s.Issuer = "http://yuhaiin.example.com" },
		func(s *OAuthServerSettings) { s.Issuer = "https://yuhaiin.example.com/path" },
		func(s *OAuthServerSettings) { s.Issuer = "" },
		func(s *OAuthServerSettings) { s.AccessTokenTTL = 60 },
		func(s *OAuthServerSettings) { s.RefreshTokenTTL = s.GrantTTL + 1 },
		func(s *OAuthServerSettings) { s.DisabledResources = []string{"unknown"} },
		func(s *OAuthServerSettings) { s.Revision++ },
	} {
		next := current
		mutate(&next)
		if _, err := o.as.SaveSettings(t.Context(), principal(o.admin), next); err == nil {
			t.Errorf("accepted %+v", next)
		}
	}
	next := current
	next.Issuer = "http://127.0.0.1:50051/"
	if saved, err := o.as.SaveSettings(t.Context(), principal(o.admin), next); err != nil || saved.Issuer != "http://127.0.0.1:50051" {
		t.Fatal(saved, err)
	}
}

// Concurrency: one code yields one token set, one refresh token yields at most
// one rotation, and races with revocation never authorize a revoked token.
func TestOAuthConcurrentExchangeRefreshAndRevocation(t *testing.T) {
	o := newOAuthTest(t)
	client := o.client("public", nil, nil)
	const workers = 8
	run := func(f func() int) []int {
		var wg sync.WaitGroup
		results := make([]int, workers)
		start := make(chan struct{})
		for i := range workers {
			wg.Go(func() {
				<-start
				results[i] = f()
			})
		}
		close(start)
		wg.Wait()
		return results
	}
	successes := func(results []int) int {
		n := 0
		for _, r := range results {
			if r == 200 {
				n++
			}
		}
		return n
	}
	code := o.code(o.admin, authorizeValues(client.ID, "/api", "nodes:read"), nil)
	if n := successes(run(func() int { s, _ := o.exchange(client.ID, code, nil, [2]string{}); return s })); n > 1 {
		t.Fatalf("one authorization code was exchanged %d times", n)
	}
	var grants int
	_ = o.store.db.QueryRowContext(t.Context(), `SELECT count(*) FROM management_oauth_grants WHERE revoked=0`).Scan(&grants)
	if grants != 0 {
		t.Fatal("a replayed code left an active grant")
	}

	access, refresh := o.tokens(o.admin, client.ID, "/api", "nodes:read")
	if n := successes(run(func() int { s, _ := o.refresh(client.ID, refresh, nil); return s })); n > 1 {
		t.Fatalf("one refresh token rotated %d times", n)
	}
	if status, _ := o.call("POST", "/api/v2/rpc/nodes.get", "Bearer "+access); status != 401 {
		t.Fatal("concurrent refresh reuse left the family active")
	}

	access, _ = o.tokens(o.admin, client.ID, "/api", "nodes:read")
	var wg sync.WaitGroup
	revoked := make(chan struct{})
	wg.Go(func() {
		_, _ = o.post(oauthRevokePath, url.Values{"token": {access}, "client_id": {client.ID}}, [2]string{})
		close(revoked)
	})
	for range workers {
		wg.Go(func() {
			for range 5 {
				_, _ = o.call("POST", "/api/v2/rpc/nodes.get", "Bearer "+access)
			}
		})
	}
	wg.Wait()
	<-revoked
	if status, _ := o.call("POST", "/api/v2/rpc/nodes.get", "Bearer "+access); status != 401 {
		t.Fatal("revoked token accepted after concurrent use")
	}

	// A permission change racing with requests takes effect for every request
	// that starts after it commits.
	u := testUser(t, o.store, "racer", Admin)
	access, _ = o.tokens(u, client.ID, "/api", "nodes:read")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	for range workers {
		wg.Go(func() {
			for ctx.Err() == nil {
				_, _ = o.call("POST", "/api/v2/rpc/nodes.get", "Bearer "+access)
			}
		})
	}
	if err := o.store.UpdateUser(t.Context(), o.admin.ID, u.ID, u.Login, NoManagement, false); err != nil {
		t.Fatal(err)
	}
	if status, _ := o.call("POST", "/api/v2/rpc/nodes.get", "Bearer "+access); status != 401 {
		t.Fatal("token accepted after the permission was withdrawn")
	}
	cancel()
	wg.Wait()
}

func TestOAuthLegacyCredentialPruningKeepsRotationHistory(t *testing.T) {
	o := newOAuthTest(t)
	client := o.client("public", nil, nil)
	_, refresh := o.tokens(o.admin, client.ID, "/api", "nodes:read")
	status, _ := o.refresh(client.ID, refresh, nil)
	if status != 200 {
		t.Fatal(status)
	}
	// Issuing ordinary credentials prunes revoked ones, but not OAuth history.
	for range 3 {
		if _, err := o.store.IssueToken(t.Context(), principal(o.admin), o.admin.ID, nil, 0); err != nil {
			t.Fatal(err)
		}
	}
	if status, body := o.refresh(client.ID, refresh, nil); status != 400 || o.events("oauth.refresh.reuse_detected") != 1 {
		t.Fatal("rotation history was pruned", status, body)
	}
	var grants []OAuthGrant
	grants, _ = o.as.Grants(t.Context(), "")
	if len(grants) != 1 || !grants[0].Revoked || grants[0].RevokedReason != "refresh_token_reuse" || grants[0].ResourceID != "api" {
		t.Fatalf("grants = %+v", grants)
	}
}
