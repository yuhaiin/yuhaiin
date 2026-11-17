package oauth

import (
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/management/permission"
)

func TestPKCES256Only(t *testing.T) {
	verifier := strings.Repeat("a", 43)
	challenge := S256Challenge(verifier)
	if !VerifyPKCE(verifier, challenge) {
		t.Fatal("valid verifier rejected")
	}
	for _, tt := range []struct{ verifier, challenge string }{
		{verifier + "b", challenge},
		{verifier, verifier},                 // plain method
		{strings.Repeat("a", 42), challenge}, // too short
		{strings.Repeat("a", 129), challenge},
		{strings.Repeat("a", 42) + "!", challenge},
		{verifier, challenge + "="},
	} {
		if VerifyPKCE(tt.verifier, tt.challenge) {
			t.Errorf("accepted %q / %q", tt.verifier, tt.challenge)
		}
	}
}

func TestRedirectURIValidationAndMatching(t *testing.T) {
	for _, tt := range []struct {
		uri    string
		public bool
		ok     bool
	}{
		{"https://app.example/callback", false, true},
		{"https://app.example/callback?x=1", false, true},
		{"http://127.0.0.1/callback", true, true},
		{"http://[::1]:8080/callback", true, true},
		{"http://localhost:3000/callback", true, true},
		{"com.example.app:/oauth", true, true},
		{"cursor://anysphere.cursor/oauth", true, true},
		{"com.example.app:/oauth", false, false},
		{"http://app.example/callback", true, false},
		{"https://*.example/callback", false, false},
		{"https://app.example/callback#frag", false, false},
		{"https://user@app.example/callback", false, false},
		{"javascript:alert(1)", true, false},
		{"data:text/html,x", true, false},
		{"file:///etc/passwd", true, false},
		{"/relative", true, false},
		{"https:///nohost", false, false},
	} {
		if err := ValidateRedirectURI(tt.uri, tt.public); (err == nil) != tt.ok {
			t.Errorf("%s public=%v: %v", tt.uri, tt.public, err)
		}
	}
	for _, tt := range []struct {
		registered, requested string
		ok                    bool
	}{
		{"https://app.example/cb", "https://app.example/cb", true},
		{"https://app.example/cb", "https://app.example/cb/", false},
		{"https://app.example/cb", "https://app.example:8443/cb", false},
		{"https://app.example/cb", "https://APP.example/cb", false},
		{"http://127.0.0.1/cb", "http://127.0.0.1:61234/cb", true},
		{"http://127.0.0.1:1/cb", "http://127.0.0.1:2/cb", true},
		{"http://127.0.0.1/cb", "http://127.0.0.1:61234/other", false},
		{"http://127.0.0.1/cb", "http://127.0.0.2:61234/cb", false},
		{"http://localhost/cb", "http://localhost:61234/cb", false},
		{"http://127.0.0.1/cb", "http://127.0.0.1:61234/cb?x=1", false},
	} {
		if MatchRedirectURI(tt.registered, tt.requested) != tt.ok {
			t.Errorf("match %s %s != %v", tt.registered, tt.requested, tt.ok)
		}
	}
}

func TestIssuerAndResourceCanonicalization(t *testing.T) {
	for raw, want := range map[string]string{"https://Yuhaiin.Example.com/": "https://yuhaiin.example.com", "http://127.0.0.1:50051": "http://127.0.0.1:50051", "http://localhost:1": "http://localhost:1"} {
		if got, err := NormalizeIssuer(raw); err != nil || got != want {
			t.Errorf("%s = %q %v", raw, got, err)
		}
	}
	for _, raw := range []string{"http://yuhaiin.example.com", "https://a.example/path", "https://a.example?x", "https://*.example", "ftp://a.example", "", "https://u@a.example"} {
		if _, err := NormalizeIssuer(raw); err == nil {
			t.Errorf("accepted issuer %q", raw)
		}
	}
	registry := &Registry{}
	if err := registry.Register(Resource{ID: "mcp", Name: "MCP", Path: "/mcp", Prefixes: []string{"/mcp"}, Scopes: []permission.Permission{permission.MCPConnect}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := registry.ForURI("https://a.example", "https://A.example/mcp/"); !ok {
		t.Fatal("canonical resource not resolved")
	}
	for _, uri := range []string{"https://a.example/mcp#x", "https://b.example/mcp", "https://a.example/mcp/extra", "https://a.example/mcp?x=1", "/mcp"} {
		if _, ok := registry.ForURI("https://a.example", uri); ok {
			t.Errorf("resolved %q", uri)
		}
	}
	if _, ok := registry.ForPath("/mcp"); !ok {
		t.Fatal("path not served")
	}
	if _, ok := registry.ForPath("/mcpx"); ok {
		t.Fatal("prefix matched a sibling path")
	}
}

func TestRegistryRejectsUnsafeResources(t *testing.T) {
	registry := &Registry{}
	base := Resource{ID: "api", Name: "API", Path: "/api", Prefixes: []string{"/api/"}, Scopes: []permission.Permission{permission.NodesRead}}
	if err := registry.Register(base); err != nil {
		t.Fatal(err)
	}
	for _, r := range []Resource{
		base,
		{ID: "x", Name: "X", Path: "/x", Prefixes: []string{"/api/"}, Scopes: base.Scopes},
		{ID: "y", Name: "Y", Path: "/y", Prefixes: []string{"/y"}, Scopes: []permission.Permission{permission.UsersManage}},
		{ID: "z", Name: "Z", Path: "/z", Prefixes: []string{"/z"}, Scopes: base.Scopes, Required: permission.NodesWrite},
		{ID: "Bad", Name: "B", Path: "/b", Prefixes: []string{"/b"}, Scopes: base.Scopes},
	} {
		if err := registry.Register(r); err == nil {
			t.Errorf("registered %+v", r)
		}
	}
}

func TestScopesComeFromThePermissionRegistry(t *testing.T) {
	scopes, err := ParseScope("nodes:read  nodes:read mcp:connect")
	if err != nil || len(scopes) != 2 {
		t.Fatal(scopes, err)
	}
	for _, scope := range []string{"users:manage", "tokens:own", "security:write", "system:execute", "roles:write", "tokens:manage", "unknown"} {
		if _, err := ParseScope(scope); err == nil {
			t.Errorf("accepted %s", scope)
		}
	}
	for _, p := range permission.DelegableValues() {
		if _, err := ParseScope(string(p)); err != nil {
			t.Errorf("delegable %s rejected", p)
		}
	}
}

func TestSecretsAreTyped(t *testing.T) {
	access := NewSecret(AccessTokenPrefix)
	if !WellFormedSecret(access, AccessTokenPrefix) || WellFormedSecret(access, RefreshTokenPrefix) || WellFormedSecret("yu_"+access[5:], AccessTokenPrefix) {
		t.Fatal("token type confusion")
	}
	if len(Hash(access)) != 32 || string(Hash(access)) == access {
		t.Fatal("hash")
	}
}
