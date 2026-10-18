package httpapi

import (
	json "encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/resolver"
)

func TestFakeIPEntriesRPC(t *testing.T) {
	fake, err := resolver.NewFakeDNS(netapi.NewErrProxy(errors.New("test proxy")), netapi.ErrorResolver(func(string) error { return nil }), t.TempDir()+"/state.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fake.Close() })
	if err := fake.Apply(contractresolver.FakeDNS{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	for i := range 31 {
		if _, err := fake.LookupIP(t.Context(), fmt.Sprintf("host-%02d.example", i)); err != nil {
			t.Fatal(err)
		}
	}
	mux := http.NewServeMux()
	RegisterV2(func(pattern string, handler func(http.ResponseWriter, *http.Request) error) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) { _ = handler(w, r) })
	}, V2Services{FakeIP: fake})
	rpc := func(operation, body string, status int) []byte {
		t.Helper()
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v2/rpc/"+operation, strings.NewReader(body)))
		if response.Code != status {
			t.Fatalf("%s: %d %s", operation, response.Code, response.Body.String())
		}
		return response.Body.Bytes()
	}
	var page listV2[contractresolver.FakeIPEntry]
	if err := json.Unmarshal(rpc("resolver.fakeip.entries", `{"page":2,"page_size":25}`, 200), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 25 || page.Page.Total != 62 || page.Page.Page != 2 {
		t.Fatalf("page: %+v", page)
	}
	if err := json.Unmarshal(rpc("resolver.fakeip.entries", `{}`, 200), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 25 || page.Page.PageSize != 25 || page.Page.Page != 1 {
		t.Fatalf("default page: %+v", page)
	}
	if err := json.Unmarshal(rpc("resolver.fakeip.entries", `{"page_size":2147483647}`, 200), &page); err != nil {
		t.Fatal(err)
	}
	if page.Page.PageSize != 100 {
		t.Fatalf("unbounded page: %+v", page)
	}
	if err := json.Unmarshal(rpc("resolver.fakeip.entries", `{"query":"HOST-00"}`, 200), &page); err != nil {
		t.Fatal(err)
	}
	if page.Page.Total != 2 || len(page.Items) != 2 {
		t.Fatalf("search: %+v", page)
	}
	body, err := json.Marshal(page.Items[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(rpc("resolver.fakeip.entry.delete", string(body), 200)) != `{"removed":1}` {
		t.Fatal("mapping was not deleted")
	}
	if string(rpc("resolver.fakeip.entry.delete", string(body), 200)) != `{"removed":0}` {
		t.Fatal("repeated delete removed mapping")
	}
	rpc("resolver.fakeip.entry.delete", `{"domain":"host-00.example","ip":"bad"}`, 400)
	rpc("resolver.fakeip.entry.delete", `{"ip":"198.18.0.1"}`, 400)
	rpc("resolver.fakeip.entry.delete", `{"domain":"host-00.example","ip":"fe80::1%eth0"}`, 400)
	rpc("resolver.fakeip.entries", `{"page":"bad"}`, 400)
	// Changing pools hides retained mappings from the former ranges.
	if err := fake.Apply(contractresolver.FakeDNS{IPv4Range: "10.0.0.0/24", IPv6Range: "fd00::/64"}); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rpc("resolver.fakeip.entries", `{}`, 200), &page); err != nil {
		t.Fatal(err)
	}
	if page.Page.Total != 0 || len(page.Items) != 0 {
		t.Fatalf("old pools visible: %+v", page)
	}
	empty := v2API{}
	if _, err := empty.fakeIPEntries(t.Context(), &listRequest{}); err == nil {
		t.Fatal("missing runtime accepted")
	}
	if _, err := empty.deleteFakeIPEntry(t.Context(), &contractresolver.FakeIPEntry{Domain: "example.com", IP: "198.18.0.1"}); err == nil {
		t.Fatal("missing deletion runtime accepted")
	}
	if err := fake.Close(); err != nil {
		t.Fatal(err)
	}
	rpc("resolver.fakeip.entries", `{}`, 500)
}
