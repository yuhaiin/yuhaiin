package auth

import (
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/access"
	"github.com/Asutorufa/yuhaiin/pkg/httpapi"
)

func TestAccessHTTPPermissionsValidationAndOwnedPreview(t *testing.T) {
	runtime, err := OpenRuntime(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	admin := testUser(t, runtime.store, "admin", Admin)
	reader := testUser(t, runtime.store, "reader", ReadOnly)
	ordinary := testUser(t, runtime.store, "ordinary", NoManagement)
	issue := func(user User, permissions []Permission) string {
		t.Helper()
		issued, err := runtime.store.IssueToken(t.Context(), principal(admin), user.ID, permissions, 0)
		if err != nil {
			t.Fatal(err)
		}
		return issued.Secret
	}
	manager := issue(admin, []Permission{TrafficAccessRead, TrafficAccessWrite, UsersManage})
	auditor := issue(reader, []Permission{TrafficAccessRead})
	user := issue(ordinary, []Permission{IdentityRead})
	proxy, err := runtime.Proxy.Issue(t.Context(), principal(reader), ProxyCredentialRequest{Name: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	handler, _, err := runtime.Middleware(t.Context(), http.NewServeMux(), httpapi.MiddlewareOptions{})
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body, secret string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "/api/v2/auth/traffic-access"+path, strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set("Authorization", "Bearer "+secret)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, endpoint := range []struct{ method, path string }{{"GET", ""}, {"GET", "/status"}, {"PUT", ""}, {"POST", "/validate"}, {"POST", "/preview"}} {
		if w := request(endpoint.method, endpoint.path, `{}`, user); w.Code != 403 {
			t.Fatal("ordinary user bypass", endpoint, w.Code)
		}
	}
	if w := request("PUT", "", `{}`, auditor); w.Code != 403 {
		t.Fatal("reader activated policy", w.Code)
	}
	config := contract.Config{Enabled: true, Scope: contract.Scope{AllInbounds: true}, DefaultAction: "allow"}
	data, _ := json.Marshal(config)
	if w := request("POST", "/validate", string(data), manager); w.Code != 200 || !strings.Contains(w.Body.String(), `"valid":true`) {
		t.Fatal("validate", w.Code, w.Body.String())
	}
	if runtime.Access.Controller.Config().Enabled {
		t.Fatal("validation activated policy")
	}
	if w := request("PUT", "", string(data), manager); w.Code != 200 {
		t.Fatal("save", w.Code)
	}
	if w := request("PUT", "", string(data), manager); w.Code != 409 {
		t.Fatal("stale revision", w.Code)
	}
	body, _ := json.Marshal(AccessPreviewRequest{CredentialID: proxy.ID, InboundID: "entry", Protocol: "tcp", Destination: "service.example:443", ResolvedIP: "192.0.2.8"})
	if w := request("POST", "/preview", string(body), auditor); w.Code != 200 || !strings.Contains(w.Body.String(), `"allowed":true`) {
		t.Fatal("own effective policy", w.Code, w.Body.String())
	}
	otherReader := testUser(t, runtime.store, "other-reader", ReadOnly)
	other := issue(otherReader, []Permission{TrafficAccessRead})
	if w := request("POST", "/preview", string(body), other); w.Code != 403 {
		t.Fatal("other user inspected identity", w.Code)
	}
	if w := request("POST", "/validate", `{"enabled":true,"scope":{"allInbounds":true},"defaultAction":"typo"}`, manager); w.Code != 200 || !strings.Contains(w.Body.String(), `"valid":false`) {
		t.Fatal("validation errors missing", w.Code, w.Body.String())
	}
	if w := request("POST", "/preview", `{"credentialId":"`+proxy.ID+`","inboundId":"entry","protocol":"tcp","destination":"service.example:443","resolvedIp":"another.example"}`, auditor); w.Code != 400 {
		t.Fatal("preview accepts unresolved address", w.Code)
	}
}
