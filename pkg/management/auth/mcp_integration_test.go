package auth

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractsettings "github.com/Asutorufa/yuhaiin/pkg/contract/settings"
	"github.com/Asutorufa/yuhaiin/pkg/httpapi"
	"github.com/Asutorufa/yuhaiin/pkg/management/oauth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type fakeSettings struct{}

func (fakeSettings) Info(context.Context) (contractsettings.Info, error) {
	return contractsettings.Info{Version: "v-test", OS: "testos"}, nil
}
func (fakeSettings) Load(context.Context) (contractsettings.Settings, error) {
	return contractsettings.Settings{}, nil
}
func (fakeSettings) Save(_ context.Context, s contractsettings.Settings) (contractsettings.Settings, error) {
	return s, nil
}

type fakeNodes struct {
	httpapi.NodeController
	mu       sync.Mutex
	selected contractnode.SelectionRequest
	block    chan struct{}
	entered  chan struct{}
}

func (f *fakeNodes) Selected(ctx context.Context) (contractnode.Selection, error) {
	if f.block != nil {
		f.entered <- struct{}{}
		select {
		case <-ctx.Done():
			close(f.block)
			return contractnode.Selection{}, ctx.Err()
		case <-time.After(10 * time.Second):
			return contractnode.Selection{}, errors.New("handler context was never cancelled")
		}
	}
	return contractnode.Selection{}, nil
}

func (f *fakeNodes) Select(_ context.Context, request contractnode.SelectionRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.selected = request
	return nil
}

type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

type mcpTest struct {
	t       *testing.T
	runtime *Runtime
	url     string
	admin   User
	client  string
	nodes   *fakeNodes
}

func newMCPTest(t *testing.T) *mcpTest {
	t.Helper()
	nodes := &fakeNodes{}
	m := newMCPTestWith(t, httpapi.V2Services{Settings: fakeSettings{}, Node: nodes})
	m.nodes = nodes
	return m
}

func newMCPTestWith(t *testing.T, services httpapi.V2Services) *mcpTest {
	t.Helper()
	runtime, err := OpenRuntime(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	mux := http.NewServeMux()
	handler, _, err := runtime.Middleware(t.Context(), mux, httpapi.MiddlewareOptions{Operations: httpapi.NewOperations(services)})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	m := &mcpTest{t: t, runtime: runtime, url: server.URL, admin: testUser(t, runtime.store, "admin", Admin)}
	runtime.Authorization.limiter = newRateLimiter(1<<20, 1<<20)
	settings, _ := runtime.Authorization.Settings(t.Context())
	settings.Enabled, settings.Issuer = true, server.URL
	if _, err := runtime.Authorization.SaveSettings(t.Context(), principal(m.admin), settings); err != nil {
		t.Fatal(err)
	}
	return m
}

// authorize performs dynamic registration, the authorization request, the
// user's consent and the token exchange over HTTP, as an MCP client would.
func (m *mcpTest) authorize(user User, scope string) (string, string) {
	m.t.Helper()
	if m.client == "" {
		response, err := http.Post(m.url+"/oauth/register", "application/json", strings.NewReader(`{"client_name":"MCP test","redirect_uris":["http://127.0.0.1/callback"],"token_endpoint_auth_method":"none"}`))
		if err != nil {
			m.t.Fatal(err)
		}
		var registered ClientRegistrationResponse
		_ = json.UnmarshalRead(response.Body, &registered)
		response.Body.Close()
		m.client = registered.ClientID
	}
	values := url.Values{"response_type": {"code"}, "client_id": {m.client}, "redirect_uri": {"http://127.0.0.1:41234/callback"}, "resource": {m.url + "/mcp"},
		"scope": {scope}, "code_challenge": {oauth.S256Challenge(testVerifier)}, "code_challenge_method": {"S256"}, "state": {"s"}}
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := noRedirect.Get(m.url + "/oauth/authorize?" + values.Encode())
	if err != nil {
		m.t.Fatal(err)
	}
	response.Body.Close()
	location := response.Header.Get("Location")
	id, ok := strings.CutPrefix(location, m.url+"/#/oauth/consent/")
	if !ok {
		m.t.Fatalf("authorize redirected to %q", location)
	}
	request, _ := m.runtime.Authorization.pendingRequest(id, false)
	redirect, err := m.runtime.Authorization.Decide(m.t.Context(), principal(user), id, true, request.Scopes)
	if err != nil {
		m.t.Fatal(err)
	}
	u, _ := url.Parse(redirect)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "redirect_uri": {"http://127.0.0.1:41234/callback"}, "code_verifier": {testVerifier}, "client_id": {m.client}, "resource": {m.url + "/mcp"}}
	response, err = http.Post(m.url+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		m.t.Fatal(err)
	}
	defer response.Body.Close()
	var tokens TokenResponse
	if err := json.UnmarshalRead(response.Body, &tokens); err != nil || response.StatusCode != 200 {
		m.t.Fatal(response.StatusCode, err)
	}
	return tokens.AccessToken, tokens.RefreshToken
}

func (m *mcpTest) connect(ctx context.Context, token string) (*mcp.ClientSession, error) {
	client := mcp.NewClient(&mcp.Implementation{Name: "yuhaiin-test", Version: "1"}, nil)
	return client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: m.url + "/mcp", HTTPClient: &http.Client{Transport: bearerTransport{token}}, DisableStandaloneSSE: true, MaxRetries: -1}, nil)
}

func toolNames(t *testing.T, session *mcp.ClientSession) []string {
	t.Helper()
	tools, err := session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	return names
}

func callText(t *testing.T, session *mcp.ClientSession, name string, arguments any) (string, bool, error) {
	t.Helper()
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: arguments})
	if err != nil {
		return "", false, err
	}
	text := ""
	for _, content := range result.Content {
		if c, ok := content.(*mcp.TextContent); ok {
			text += c.Text
		}
	}
	return text, result.IsError, nil
}

func TestMCPOAuthDiscoveryAndChallenge(t *testing.T) {
	m := newMCPTest(t)
	response, err := http.Post(m.url+"/mcp", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	challenge := response.Header.Get("WWW-Authenticate")
	want := `resource_metadata="` + m.url + `/.well-known/oauth-protected-resource/mcp"`
	if response.StatusCode != 401 || !strings.HasPrefix(challenge, "Bearer ") || !strings.Contains(challenge, want) {
		t.Fatalf("challenge = %d %q", response.StatusCode, challenge)
	}
	response, _ = http.Get(m.url + "/.well-known/oauth-protected-resource/mcp")
	var prm oauth.ProtectedResourceMetadata
	_ = json.UnmarshalRead(response.Body, &prm)
	response.Body.Close()
	if prm.Resource != m.url+"/mcp" || len(prm.AuthorizationServers) != 1 || !slices.Contains(prm.ScopesSupported, "mcp:connect") || !slices.Contains(prm.ScopesSupported, "nodes:write") {
		t.Fatalf("resource metadata = %+v", prm)
	}
	response, _ = http.Get(prm.AuthorizationServers[0] + "/.well-known/oauth-authorization-server")
	var metadata oauth.AuthorizationServerMetadata
	_ = json.UnmarshalRead(response.Body, &metadata)
	response.Body.Close()
	if metadata.Issuer != m.url || metadata.RegistrationEndpoint != m.url+"/oauth/register" {
		t.Fatalf("authorization server metadata = %+v", metadata)
	}
	// Session cookies and API tokens are not MCP credentials.
	token, _ := m.runtime.store.IssueToken(t.Context(), principal(m.admin), m.admin.ID, nil, 0)
	if _, err := m.connect(t.Context(), token.Secret); err == nil {
		t.Fatal("API token connected to MCP")
	}
	// The management API answers 401 with its own resource metadata.
	response, _ = http.Post(m.url+"/api/v2/rpc/info", "application/json", nil)
	response.Body.Close()
	if !strings.Contains(response.Header.Get("WWW-Authenticate"), "/.well-known/oauth-protected-resource/api") {
		t.Fatal("API challenge", response.Header)
	}
}

func TestMCPToolsFollowGrantedPermissions(t *testing.T) {
	m := newMCPTest(t)
	access, _ := m.authorize(m.admin, "mcp:connect settings:read")
	session, err := m.connect(t.Context(), access)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if info := session.InitializeResult(); info == nil || info.ServerInfo.Name != "yuhaiin" || info.ProtocolVersion == "" {
		t.Fatalf("initialize = %+v", info)
	}
	if names := toolNames(t, session); !slices.Equal(names, []string{"get_settings", "get_system_info", "get_system_network"}) {
		t.Fatalf("tools = %v", names)
	}
	text, isError, err := callText(t, session, "get_system_info", map[string]any{})
	if err != nil || isError || !strings.Contains(text, `"version":"v-test"`) {
		t.Fatal(text, isError, err)
	}
	if _, isError, err := callText(t, session, "get_system_info", map[string]any{"unexpected": true}); err == nil && !isError {
		t.Fatal("unknown argument accepted")
	}
	// A tool outside the grant is neither listed nor callable.
	if text, isError, err := callText(t, session, "select_node", map[string]any{"node_id": "n1"}); err == nil && !isError {
		t.Fatal("unauthorized tool ran", text)
	}
	if m.nodes.selected.TCPID != "" {
		t.Fatal("unauthorized tool changed state")
	}

	write, _ := m.authorize(m.admin, "mcp:connect nodes:read nodes:write")
	writer, err := m.connect(t.Context(), write)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if names := toolNames(t, writer); !slices.Contains(names, "select_node") || !slices.Contains(names, "list_nodes") || slices.Contains(names, "get_settings") || slices.Contains(names, "close_connections") {
		t.Fatalf("tools = %v", names)
	}
	if _, isError, err := callText(t, writer, "select_node", map[string]any{"node_id": "n1"}); err != nil || isError {
		t.Fatal(isError, err)
	}
	if m.nodes.selected != (contractnode.SelectionRequest{TCPID: "n1", UDPID: "n1"}) {
		t.Fatalf("selection = %+v", m.nodes.selected)
	}
	if _, isError, _ := callText(t, writer, "select_node", map[string]any{}); !isError {
		t.Fatal("missing required argument accepted")
	}
	// A controller that is not configured is reported as a tool error.
	if text, isError, err := callText(t, writer, "update_subscription", map[string]any{"names": []string{"a"}}); err != nil || !isError || !strings.Contains(text, "unavailable") {
		t.Fatal(text, isError, err)
	}
	tools, _ := writer.ListTools(t.Context(), nil)
	for _, tool := range tools.Tools {
		if tool.Name == "select_node" && (tool.Annotations == nil || tool.Annotations.ReadOnlyHint) {
			t.Fatal("select_node is annotated read-only")
		}
		if tool.Name == "list_nodes" && (tool.Annotations == nil || !tool.Annotations.ReadOnlyHint) {
			t.Fatal("list_nodes is not annotated read-only")
		}
	}
}

func TestMCPRevocationAndPermissionChangesApplyToNextCall(t *testing.T) {
	m := newMCPTest(t)
	user := testUser(t, m.runtime.store, "operator", Admin)
	access, refresh := m.authorize(user, "mcp:connect nodes:read nodes:write")
	session, err := m.connect(t.Context(), access)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if _, isError, err := callText(t, session, "select_node", map[string]any{"node_id": "n2"}); err != nil || isError {
		t.Fatal(isError, err)
	}
	// Demotion removes nodes:write; the grant exceeding it is revoked at once.
	if err := m.runtime.store.UpdateUser(t.Context(), m.admin.ID, user.ID, user.Login, ReadOnly, false); err != nil {
		t.Fatal(err)
	}
	if _, isError, err := callText(t, session, "select_node", map[string]any{"node_id": "n3"}); err == nil && !isError {
		t.Fatal("tool ran after the grant's permission was withdrawn")
	}
	if m.nodes.selected.TCPID != "n2" {
		t.Fatal("state changed after demotion")
	}
	// Revocation through RFC 7009 ends the next request too.
	access, _ = m.authorize(m.admin, "mcp:connect settings:read")
	session2, err := m.connect(t.Context(), access)
	if err != nil {
		t.Fatal(err)
	}
	defer session2.Close()
	response, _ := http.Post(m.url+"/oauth/revoke", "application/x-www-form-urlencoded", strings.NewReader(url.Values{"token": {access}, "client_id": {m.client}}.Encode()))
	response.Body.Close()
	if _, _, err := callText(t, session2, "get_system_info", map[string]any{}); err == nil {
		t.Fatal("revoked token still calls tools")
	}
	_ = refresh
}

func TestMCPToolCallCancellation(t *testing.T) {
	m := newMCPTest(t)
	access, _ := m.authorize(m.admin, "mcp:connect nodes:read")
	session, err := m.connect(t.Context(), access)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	m.nodes.block, m.nodes.entered = make(chan struct{}), make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "get_selected_node", Arguments: map[string]any{}})
		done <- err
	}()
	select {
	case <-m.nodes.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("tool did not start")
	}
	// The client gives up (disconnects); the server-side operation must stop.
	cancel()
	select {
	case <-m.nodes.block:
	case <-time.After(5 * time.Second):
		t.Fatal("operation context was not cancelled when the client disconnected")
	}
	if err := <-done; err == nil {
		t.Fatal("cancelled call succeeded")
	}
	_, _ = io.Discard.Write(nil)
}
