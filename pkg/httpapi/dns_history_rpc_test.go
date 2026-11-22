package httpapi

import (
	"context"
	json "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	contractdnshistory "github.com/Asutorufa/yuhaiin/pkg/contract/dnshistory"
	managementpermission "github.com/Asutorufa/yuhaiin/pkg/management/permission"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/statistics"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func newTestDNSHistory(t *testing.T) *statistics.DNSHistory {
	t.Helper()
	store, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	h, err := statistics.NewDNSHistory(store.DB(), statistics.DNSHistoryOptions{FlushInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	for _, name := range []string{"a.example.", "b.example."} {
		trace := h.BeginDNS("udp", netapi.DNSSourceLocal)
		trace.SetQuery(&dns.Msg{Question: []dns.RR{&dns.A{Hdr: dns.Header{Name: name, Class: dns.ClassINET}}}}, 30)
		trace.Finish(context.DeadlineExceeded)
	}
	deadline := time.Now().Add(5 * time.Second)
	for h.Status().Persisted < 2 {
		if time.Now().After(deadline) {
			t.Fatal("records were not persisted")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return h
}

func TestDNSHistoryRPC(t *testing.T) {
	h := newTestDNSHistory(t)
	mux := http.NewServeMux()
	RegisterV2(func(pattern string, handler func(http.ResponseWriter, *http.Request) error) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) { _ = handler(w, r) })
	}, V2Services{DNSHistory: h})
	rpc := func(operation, body string, status int) []byte {
		t.Helper()
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v2/rpc/"+operation, strings.NewReader(body)))
		if response.Code != status {
			t.Fatalf("%s: %d %s", operation, response.Code, response.Body.String())
		}
		return response.Body.Bytes()
	}
	var page contractdnshistory.ListResponse
	if err := json.Unmarshal(rpc("dns.history.list", `{"limit":1,"outcome":"timeout"}`, 200), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 || len(page.Items) != 1 || page.NextCursor == "" || page.Items[0].Outcome != "timeout" {
		t.Fatalf("page = %+v", page)
	}
	var record contractdnshistory.Record
	if err := json.Unmarshal(rpc("dns.history.get", `{"id":`+jsonNumber(page.Items[0].ID)+`}`, 200), &record); err != nil || record.Details == nil {
		t.Fatalf("record = %+v %v", record, err)
	}
	rpc("dns.history.get", `{"id":0}`, 400)
	rpc("dns.history.get", `{"id":424242}`, 404)
	rpc("dns.history.list", `{"outcome":"bogus"}`, 400)
	rpc("dns.history.list", `{"cursor":"%%%"}`, 400)
	var stats contractdnshistory.Stats
	if err := json.Unmarshal(rpc("dns.history.stats", `{}`, 200), &stats); err != nil || stats.Total != 2 || stats.Timeout != 2 || !stats.Recorder.Enabled {
		t.Fatalf("stats = %+v %v", stats, err)
	}
	rpc("dns.history.settings.put", `{"enabled":true,"retentionHours":0,"maxRecords":1000}`, 400)
	var settings contractdnshistory.Settings
	if err := json.Unmarshal(rpc("dns.history.settings.put", `{"enabled":false,"retentionHours":24,"maxRecords":1000}`, 200), &settings); err != nil || settings.Enabled {
		t.Fatalf("settings = %+v %v", settings, err)
	}
	if err := json.Unmarshal(rpc("dns.history.settings.get", `{}`, 200), &settings); err != nil || settings.RetentionHours != 24 {
		t.Fatalf("settings get = %+v %v", settings, err)
	}
	if string(rpc("dns.history.clear", `{}`, 200)) != `{"deleted":2}` {
		t.Fatal("history was not cleared")
	}

	empty := http.NewServeMux()
	RegisterV2(func(pattern string, handler func(http.ResponseWriter, *http.Request) error) {
		empty.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) { _ = handler(w, r) })
	}, V2Services{})
	response := httptest.NewRecorder()
	empty.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v2/rpc/dns.history.list", strings.NewReader(`{}`)))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing history = %d", response.Code)
	}
}

func jsonNumber(v int64) string {
	data, _ := json.Marshal(v)
	return string(data)
}

// DNS history is privacy-sensitive: connections:read is not enough, and
// clearing or reconfiguring requires the write permission.
func TestDNSHistoryOperationPermissions(t *testing.T) {
	ops := NewOperations(V2Services{DNSHistory: newTestDNSHistory(t)})
	as := func(p ...managementpermission.Permission) context.Context {
		return managementpermission.WithGranted(t.Context(), p)
	}
	if _, err := ops.Invoke(as(managementpermission.ConnectionsRead, managementpermission.ResolverRead), "dns.history.list", []byte(`{}`)); err == nil {
		t.Fatal("history readable without dns-history:read")
	}
	if _, err := ops.Invoke(t.Context(), "dns.history.stats", []byte(`{}`)); err == nil {
		t.Fatal("unauthenticated context allowed")
	}
	if _, err := ops.Invoke(as(managementpermission.DNSHistoryRead), "dns.history.list", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := ops.Invoke(as(managementpermission.DNSHistoryRead), "dns.history.clear", []byte(`{}`)); err == nil {
		t.Fatal("clear allowed with read permission")
	}
	if _, err := ops.Invoke(as(managementpermission.DNSHistoryRead), "dns.history.settings.put", []byte(`{"enabled":false,"retentionHours":1,"maxRecords":100}`)); err == nil {
		t.Fatal("settings change allowed with read permission")
	}
	if _, err := ops.Invoke(as(managementpermission.DNSHistoryWrite), "dns.history.clear", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []v2Endpoint{v2DNSHistoryList, v2DNSHistoryGet, v2DNSHistoryStats, v2DNSHistorySettingsGet} {
		if v2Permissions[endpoint] != managementpermission.DNSHistoryRead {
			t.Errorf("%s = %s", endpoint, v2Permissions[endpoint])
		}
	}
}
