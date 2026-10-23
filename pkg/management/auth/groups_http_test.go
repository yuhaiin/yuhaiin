package auth

import (
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/httpapi"
)

func TestGroupHTTPPermissionsAndImmediateRevocation(t *testing.T) {
	runtime, err := OpenRuntime(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	admin := testUser(t, runtime.store, "admin", Admin)
	alice := testUser(t, runtime.store, "alice", NoManagement)
	manager, err := runtime.store.IssueToken(t.Context(), principal(admin), admin.ID, []Permission{UsersManage}, 0)
	if err != nil {
		t.Fatal(err)
	}
	user, err := runtime.store.IssueToken(t.Context(), principal(admin), alice.ID, []Permission{IdentityRead}, 0)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := runtime.Proxy.Issue(t.Context(), principal(alice), ProxyCredentialRequest{Name: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := runtime.Proxy.Verifier("entry", "http", []string{alice.ID})(t.Context(), alice.Login, []byte(credential.Secret))
	if err != nil {
		t.Fatal(err)
	}
	handler, _, err := runtime.Middleware(t.Context(), http.NewServeMux(), httpapi.MiddlewareOptions{})
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
	for _, method := range []string{"GET", "POST", "PUT", "DELETE"} {
		path := "/api/v2/auth/groups"
		if method == "PUT" || method == "DELETE" {
			path += "/finance?revision=1"
		}
		if response := request(method, path, `{"name":"Finance","members":["`+alice.ID+`"]}`, user.Secret); response.Code != 403 {
			t.Fatalf("user escalated memberships via %s: %d", method, response.Code)
		}
	}
	response := request("POST", "/api/v2/auth/groups", `{"name":"Finance","members":["`+alice.ID+`"]}`, manager.Secret)
	if response.Code != 200 {
		t.Fatalf("create status=%d", response.Code)
	}
	if identity.Valid() {
		t.Fatal("successful response preceded traffic revocation")
	}
	var group Group
	if err := json.Unmarshal(response.Body.Bytes(), &group); err != nil {
		t.Fatal(err)
	}
	if response := request("PUT", "/api/v2/auth/groups/"+group.ID, `{"name":"stale","revision":0}`, manager.Secret); response.Code != 409 {
		t.Fatalf("stale update=%d", response.Code)
	}
	if response := request("GET", "/api/v2/auth/groups/"+group.ID, "", manager.Secret); response.Code != 200 {
		t.Fatalf("inspect=%d", response.Code)
	}
}
