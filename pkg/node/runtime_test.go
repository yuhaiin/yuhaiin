package node

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func newTestRuntime(t *testing.T) *NodeRuntime {
	t.Helper()
	runtime := NewNodeRuntime(paths.PathGenerator.State(t.TempDir()))
	t.Cleanup(func() { _ = runtime.Close() })
	return runtime
}

func TestAddNode(t *testing.T) {
	runtime := newTestRuntime(t)

	for _, item := range []contractnode.Node{
		testNode(t, "a", "feefe"),
		testNode(t, "b", "fafaf"),
		testNode(t, "c", "fazczfzf"),
		testNode(t, "d", "fazczfzf"),
	} {
		if _, err := runtime.Save(t.Context(), item); err != nil {
			t.Fatal(err)
		}
	}

	if err := runtime.AddContractTag(t.Context(), "test_tag", "tag", "b"); err != nil {
		t.Fatal(err)
	}
	if err := runtime.AddContractTag(t.Context(), "test_tag3", "node", "c"); err != nil {
		t.Fatal(err)
	}
	if err := runtime.AddContractTag(t.Context(), "test_tag2", "node", "b"); err != nil {
		t.Fatal(err)
	}
	if err := runtime.AddContractTag(t.Context(), "test_tag2", "node", "c"); err != nil {
		t.Fatal(err)
	}
	if err := runtime.DeleteTag(t.Context(), "test_tag2"); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Remove(t.Context(), "c"); err != nil {
		t.Fatal(err)
	}
}

func TestContractOnlyNodeOutbound(t *testing.T) {
	runtime := newTestRuntime(t)
	input := testNode(t, "contract-outbound", "contract-outbound-node")
	if _, err := runtime.Save(t.Context(), input); err != nil {
		t.Fatalf("save contract node failed: %v", err)
	}
	if err := runtime.Use(t.Context(), input.ID); err != nil {
		t.Fatalf("use contract node failed: %v", err)
	}
	if _, err := runtime.GetDialerByID(t.Context(), input.ID); err != nil {
		t.Fatalf("get contract node dialer by id failed: %v", err)
	}
	if _, err := runtime.Get(t.Context(), "tcp", "proxy", ""); err != nil {
		t.Fatalf("get selected contract node dialer failed: %v", err)
	}
}

func TestActiveContractOnlyReturnsRuntimeDialers(t *testing.T) {
	runtime := newTestRuntime(t)
	a := testNode(t, "active-a", "active-a-node")
	b := testNode(t, "active-b", "active-b-node")
	for _, item := range []contractnode.Node{a, b} {
		if _, err := runtime.Save(t.Context(), item); err != nil {
			t.Fatalf("save contract node failed: %v", err)
		}
	}

	if active, _ := runtime.Active(t.Context()); len(active) != 0 {
		t.Fatalf("active before dialer creation = %+v", active)
	}
	if _, err := runtime.GetDialerByID(t.Context(), a.ID); err != nil {
		t.Fatalf("create active-a dialer failed: %v", err)
	}
	active, _ := runtime.Active(t.Context())
	if len(active) != 1 || active[0].ID != a.ID {
		t.Fatalf("active after active-a dialer creation = %+v", active)
	}
	if _, err := runtime.GetDialerByID(t.Context(), b.ID); err != nil {
		t.Fatalf("create active-b dialer failed: %v", err)
	}
	active, _ = runtime.Active(t.Context())
	if len(active) != 2 || active[0].ID != a.ID || active[1].ID != b.ID {
		t.Fatalf("active after both dialers creation = %+v", active)
	}
	runtime.proxies.Delete(a.ID)
	active, _ = runtime.Active(t.Context())
	if len(active) != 1 || active[0].ID != b.ID {
		t.Fatalf("active after deleting active-a = %+v", active)
	}
}

func TestExtraInfoReadsOnlyCachedProxy(t *testing.T) {
	runtime := newTestRuntime(t)
	want := contractnode.NodeExtraInfo{GlobalProtect: &contractnode.GlobalProtectInfo{
		TunnelPrefix:     "192.0.2.8/32",
		AccessRoutesIPv4: []string{"198.51.100.0/24"},
	}}
	if _, err := runtime.proxies.LoadOrCreate(t.Context(), "pa-node", func() (*ProxyEntry, error) {
		return &ProxyEntry{
			Proxy: extraInfoTestProxy{
				Proxy: netapi.NewErrProxy(errors.New("proxy must not be used to fetch runtime information")),
				info:  want,
			},
		}, nil
	}); err != nil {
		t.Fatalf("seed cached proxy: %v", err)
	}

	got, err := runtime.ExtraInfo(t.Context(), "pa-node")
	if err != nil {
		t.Fatalf("read cached extra info: %v", err)
	}
	if got.GlobalProtect == nil || got.GlobalProtect.TunnelPrefix != want.GlobalProtect.TunnelPrefix ||
		len(got.GlobalProtect.AccessRoutesIPv4) != 1 || got.GlobalProtect.AccessRoutesIPv4[0] != "198.51.100.0/24" {
		t.Fatalf("extra info = %+v, want %+v", got, want)
	}
	if _, err := runtime.ExtraInfo(t.Context(), "inactive-node"); !errors.Is(err, plainstore.ErrNotFound) {
		t.Fatalf("inactive node error = %v, want %v", err, plainstore.ErrNotFound)
	}
}

func TestLatencyUsesNodeHTTPURLOverride(t *testing.T) {
	requestedPath := make(chan string, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requestedPath <- request.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	runtime := newTestRuntime(t)
	node := testNode(t, "latency-override", "latency-override-node")
	node.Latency = &contractnode.LatencyConfig{
		URL:                strings.Replace(server.URL, "https://", "HTTPS://", 1) + "/health",
		InsecureSkipVerify: true,
	}
	if _, err := runtime.Save(t.Context(), node); err != nil {
		t.Fatalf("save node with latency override: %v", err)
	}

	result, err := runtime.Latency(t.Context(), node.ID, contractnode.LatencyRequest{
		Type: "tcp",
		URL:  "http://global.example.test/ping",
	})
	if err != nil {
		t.Fatalf("test node latency URL: %v", err)
	}
	if !result.OK {
		t.Fatalf("latency result = %+v, want success", result)
	}
	if got := <-requestedPath; got != "/health" {
		t.Fatalf("request path = %q, want per-node /health URL", got)
	}
}

type extraInfoTestProxy struct {
	netapi.Proxy
	info contractnode.NodeExtraInfo
}

func (p extraInfoTestProxy) NodeExtraInfo() contractnode.NodeExtraInfo { return p.info }

func testNode(t *testing.T, id, name string) contractnode.Node {
	t.Helper()
	protocol, err := contractnode.NewTypedProtocol(contractnode.Direct{})
	if err != nil {
		t.Fatal(err)
	}
	return contractnode.Node{
		ID:      id,
		Name:    name,
		Group:   "group",
		Origin:  "manual",
		Enabled: true,
		Chain:   []contractnode.Protocol{protocol},
	}
}
