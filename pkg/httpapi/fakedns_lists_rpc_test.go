package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	managementpermission "github.com/Asutorufa/yuhaiin/pkg/management/permission"
)

type fakeDNSListRefsStub struct {
	ResolverConfigController
	current contractresolver.FakeDNS
}

func (s *fakeDNSListRefsStub) FakeDNS(context.Context) (contractresolver.FakeDNS, error) {
	return s.current, nil
}

func (s *fakeDNSListRefsStub) SaveFakeDNS(_ context.Context, req contractresolver.FakeDNS) (contractresolver.FakeDNS, error) {
	s.current = req
	return req, nil
}

func TestV2FakeDNSListRefsRequireRoutesRead(t *testing.T) {
	stub := &fakeDNSListRefsStub{current: contractresolver.FakeDNS{WhitelistListIDs: []string{"vpn"}}}
	mux := http.NewServeMux()
	RegisterV2(func(pattern string, handler func(http.ResponseWriter, *http.Request) error) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) { _ = handler(w, r) })
	}, V2Services{ResolverConfig: stub})
	put := func(granted []managementpermission.Permission, body string) int {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/api/v2/rpc/resolver.fakedns.put", strings.NewReader(body))
		if granted != nil {
			r = r.WithContext(managementpermission.WithGranted(r.Context(), granted))
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w.Code
	}
	resolverOnly := []managementpermission.Permission{managementpermission.ResolverWrite}

	// Other settings stay editable while the references are kept as they are.
	if code := put(resolverOnly, `{"enabled":true,"whitelist":["a.example"],"whitelistListIds":["vpn"]}`); code != http.StatusOK {
		t.Fatalf("unchanged references = %d", code)
	}
	if code := put(resolverOnly, `{"whitelistListIds":["vpn"],"skipCheckListIds":["other"]}`); code != http.StatusForbidden {
		t.Fatalf("changed references without routes:read = %d", code)
	}
	if code := put(append(resolverOnly, managementpermission.RoutesRead), `{"skipCheckListIds":["other"]}`); code != http.StatusOK {
		t.Fatalf("changed references with routes:read = %d", code)
	}
	if code := put(nil, `{}`); code != http.StatusOK {
		t.Fatalf("unauthenticated in-process call = %d", code)
	}
}
