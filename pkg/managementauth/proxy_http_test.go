package managementauth

import (
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/httpapi"
)

func TestProxyCredentialRoutesRespectOwnersAndCredentialDomains(t *testing.T) {
	runtime, err := OpenRuntime(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	admin := testUser(t, runtime.store, "admin", Admin)
	alice := testUser(t, runtime.store, "alice", NoManagement)
	bob := testUser(t, runtime.store, "bob", NoManagement)
	// Tokens can exercise HTTP authorization without repeating password-KDF tests.
	token, err := runtime.store.IssueToken(t.Context(), principal(admin), alice.ID, []Permission{IdentityRead, ProxyCredentialsOwn}, 0)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	handler, _, err := runtime.Middleware(t.Context(), mux, httpapi.MiddlewareOptions{})
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body, secret string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set("Authorization", "Bearer "+secret)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	created := request("POST", "/api/v2/auth/proxy-credentials", `{"name":"phone"}`, token.Secret)
	if created.Code != 200 {
		t.Fatalf("create %d %s", created.Code, created.Body)
	}
	var issued IssuedProxyCredential
	if err = json.Unmarshal(created.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	if issued.UserID != alice.ID || issued.Secret == "" {
		t.Fatal("wrong issued credential")
	}
	listed := request("GET", "/api/v2/auth/proxy-credentials", "", token.Secret)
	if listed.Code != 200 || strings.Contains(listed.Body.String(), issued.Secret) {
		t.Fatalf("list %d %s", listed.Code, listed.Body)
	}
	if w := request("GET", "/api/v2/auth/proxy-credentials?owner="+bob.ID, "", token.Secret); w.Code != 403 {
		t.Fatal("read another owner's credentials")
	}
	if w := request("POST", "/api/v2/auth/proxy-credentials", `{"owner":"`+bob.ID+`","name":"other"}`, token.Secret); w.Code != 403 {
		t.Fatal("created another owner's credential")
	}
	if w := request("GET", "/api/v2/auth/upstream-credentials", "", token.Secret); w.Code != 403 {
		t.Fatal("proxy-only user accessed upstream credentials")
	}
	if w := request("GET", "/api/v2/auth/me", "", issued.Secret); w.Code != 401 {
		t.Fatal("proxy secret authenticated to management")
	}
}
