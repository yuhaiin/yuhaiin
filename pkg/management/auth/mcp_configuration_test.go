package auth

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	contractinbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/httpapi"
	"github.com/Asutorufa/yuhaiin/pkg/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// storeNodes is the node controller over the real SQLite node store. Only the
// latency probe, which would contact the network, is simulated.
type storeNodes struct {
	httpapi.NodeController
	store   *plainstore.NodeStore
	mu      sync.Mutex
	latency []string
}

func (s *storeNodes) Save(ctx context.Context, node contractnode.Node) (contractnode.Node, error) {
	if err := s.store.Save(ctx, node, 0); err != nil {
		return contractnode.Node{}, err
	}
	return s.store.Get(ctx, node.ID)
}
func (s *storeNodes) Remove(ctx context.Context, id string) error { return s.store.Delete(ctx, id) }
func (s *storeNodes) Latency(ctx context.Context, id string, request contractnode.LatencyRequest) (contractnode.LatencyResponse, error) {
	if _, err := s.store.Get(ctx, id); err != nil {
		return contractnode.LatencyResponse{}, err
	}
	s.mu.Lock()
	s.latency = append(s.latency, id+" "+request.Type)
	s.mu.Unlock()
	return contractnode.LatencyResponse{}, nil
}

// storeResolvers is the resolver controller over the real resolver store; the
// DNS query of a test is simulated.
type storeResolvers struct{ store *plainstore.ResolverStore }

func (s storeResolvers) Save(ctx context.Context, r contractresolver.Resolver) (contractresolver.Resolver, error) {
	if err := s.store.Save(ctx, r, 0); err != nil {
		return contractresolver.Resolver{}, err
	}
	return s.store.Get(ctx, r.ID)
}
func (s storeResolvers) Remove(ctx context.Context, id string) error { return s.store.Delete(ctx, id) }
func (s storeResolvers) Test(_ context.Context, r contractresolver.TestRequest) (contractresolver.TestResponse, error) {
	if r.Resolver.Host == "" {
		return contractresolver.TestResponse{}, errors.New("resolver host is required")
	}
	return contractresolver.TestResponse{Domain: r.Domain, QueryType: r.QueryType}, nil
}

// routeRuntime records activations and answers route tests from the saved rules.
type routeRuntime struct {
	rules   *plainstore.RouteRuleStore
	mu      sync.Mutex
	applied int
}

func (r *routeRuntime) ScheduleApply() {}
func (r *routeRuntime) Apply(context.Context) error {
	r.mu.Lock()
	r.applied++
	r.mu.Unlock()
	return nil
}
func (r *routeRuntime) ActivationStatus(context.Context) (contractroute.RuleActivationStatus, error) {
	return contractroute.RuleActivationStatus{}, nil
}
func (r *routeRuntime) Test(_ context.Context, host string) (contractroute.RuleTestResponse, error) {
	return contractroute.RuleTestResponse{Mode: "direct", AfterAddr: host}, nil
}
func (r *routeRuntime) BlockHistory(context.Context) (contractroute.BlockHistoryList, error) {
	return contractroute.BlockHistoryList{}, nil
}

type mcpConfigFixture struct {
	*mcpTest
	nodes  *storeNodes
	routes *routeRuntime
}

func newMCPConfigFixture(t *testing.T) *mcpConfigFixture {
	t.Helper()
	db, err := storagesqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	runtime := inbound.NewInbound(netapi.NewErrProxy(errors.New("test has no outbound")))
	t.Cleanup(func() { _ = runtime.Close(); _ = db.Close() })
	gateways, err := gateway.NewManager(t.Context(), plainstore.NewGatewayStore(db.DB()), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gateways.Close() })
	nodes := &storeNodes{store: plainstore.NewNodeStore(db.DB())}
	rules := plainstore.NewRouteRuleStore(db.DB())
	routes := &routeRuntime{rules: rules}
	services := httpapi.V2Services{
		Nodes: nodes.store, Node: nodes,
		Inbounds:  inbound.NewContractStore(plainstore.NewInboundStore(db.DB()), runtime),
		Gateway:   gateways,
		Resolvers: plainstore.NewResolverStore(db.DB()), Resolver: storeResolvers{plainstore.NewResolverStore(db.DB())},
		ResolverConfig: plainstore.NewResolverConfigStore(db.DB()),
		RouteRules:     rules, RouteLists: plainstore.NewRouteListStore(db.DB()), RouteEditor: plainstore.NewRouteEditorStore(db.DB()), Rules: routes,
	}
	return &mcpConfigFixture{mcpTest: newMCPTestWith(t, services), nodes: nodes, routes: routes}
}

// call runs a tool and fails the test on a protocol or tool error.
func call(t *testing.T, session *mcp.ClientSession, name string, arguments any) map[string]any {
	t.Helper()
	text, isError, err := callText(t, session, name, arguments)
	if err != nil || isError {
		t.Fatalf("%s: %v %s", name, err, text)
	}
	out := map[string]any{}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("%s returned %q: %v", name, text, err)
	}
	return out
}

// conforms checks that a value read from the API validates against the input
// schema of the tool that saves it, so read-modify-save works.
func conforms(t *testing.T, session *mcp.ClientSession, tool string, value map[string]any) {
	t.Helper()
	tools, err := session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range tools.Tools {
		if candidate.Name != tool {
			continue
		}
		encoded, _ := json.Marshal(candidate.InputSchema)
		var schema jsonschema.Schema
		if err := json.Unmarshal(encoded, &schema); err != nil {
			t.Fatal(err)
		}
		resolved, err := schema.Resolve(nil)
		if err != nil {
			t.Fatalf("%s schema: %v", tool, err)
		}
		if err := resolved.Validate(value); err != nil {
			t.Fatalf("%s rejects what the API returns: %v\n%v", tool, err, value)
		}
		return
	}
	t.Fatalf("tool %s is not listed", tool)
}

const shareLink = "ss://YWVzLTI1Ni1nY206bXktdmVyeS1wcml2YXRlLXBhc3N3b3Jk@192.0.2.10:8388#Tokyo"

func TestMCPConfigurationToolsAddAndTestEverything(t *testing.T) {
	f := newMCPConfigFixture(t)
	access, _ := f.authorize(f.admin, "")
	session, err := f.connect(t.Context(), access)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	t.Run("nodes", func(t *testing.T) {
		preview := call(t, session, "preview_node_import", map[string]any{"text": shareLink})
		if items, _ := preview["items"].([]any); len(items) != 1 {
			t.Fatalf("preview = %v", preview)
		}
		imported := call(t, session, "import_nodes", map[string]any{"text": shareLink, "group": "imported"})
		results := imported["results"].(map[string]any)["items"].([]any)
		saved := results[0].(map[string]any)
		if saved["saved"] != true {
			t.Fatalf("import = %v", imported)
		}
		id := saved["id"].(string)
		node := call(t, session, "get_node", map[string]any{"id": id})
		encoded, _ := json.Marshal(node)
		if !strings.Contains(node["name"].(string), "Tokyo") || node["group"] != "imported" || strings.Contains(string(encoded), "my-very-private-password") {
			t.Fatalf("node = %s", encoded)
		}
		conforms(t, session, "save_node", node)
		// Read, modify and save back with the redacted secret.
		node["name"] = "Tokyo 2"
		if renamed := call(t, session, "save_node", node); renamed["name"] != "Tokyo 2" {
			t.Fatalf("save = %v", renamed)
		}
		stored, _ := f.nodes.store.Get(t.Context(), id)
		storedJSON, _ := json.Marshal(stored)
		if !strings.Contains(string(storedJSON), "my-very-private-password") {
			t.Fatalf("saving a redacted node lost its secret: %s", storedJSON)
		}
		// A new node from scratch gets an id.
		created := call(t, session, "save_node", map[string]any{"name": "Direct", "group": "manual", "origin": "manual", "enabled": true,
			"chain": []any{map[string]any{"type": "direct", "direct": map[string]any{}}}})
		if created["id"] == "" || created["id"] == nil {
			t.Fatalf("created = %v", created)
		}
		call(t, session, "test_node_latency", map[string]any{"id": id, "type": "http", "url": "https://www.google.com/generate_204"})
		if len(f.nodes.latency) != 1 {
			t.Fatal("latency test did not run")
		}
		if listed := call(t, session, "list_nodes", map[string]any{"group": "imported"}); len(listed["items"].([]any)) != 1 {
			t.Fatalf("list = %v", listed)
		}
		call(t, session, "delete_node", map[string]any{"id": created["id"]})
		if _, err := f.nodes.store.Get(t.Context(), created["id"].(string)); err == nil {
			t.Fatal("node not deleted")
		}
	})

	t.Run("inbounds", func(t *testing.T) {
		capabilities := call(t, session, "get_inbound_capabilities", map[string]any{})
		if protocols, _ := capabilities["protocols"].([]any); len(protocols) == 0 {
			t.Fatalf("capabilities = %v", capabilities)
		}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.Addr().String()
		_ = listener.Close()
		in := contractinbound.Inbound{Name: "Local mixed", Enabled: true, Network: contractinbound.NewTypedNetwork(contractinbound.TCPUDPNetwork{Host: address, UDP: contractinbound.UDPDisabled}), Protocol: contractinbound.NewTypedProtocol(contractinbound.MixedProtocol{})}
		var arguments map[string]any
		encoded, _ := json.Marshal(in)
		_ = json.Unmarshal(encoded, &arguments)
		delete(arguments, "id")
		saved := call(t, session, "save_inbound", arguments)
		id := saved["id"].(string)
		// The listener is really running.
		conn, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal("inbound is not listening:", err)
		}
		_ = conn.Close()
		got := call(t, session, "get_inbound", map[string]any{"id": id})
		conforms(t, session, "save_inbound", got)
		call(t, session, "get_inbound_status", map[string]any{})
		call(t, session, "delete_inbound", map[string]any{"id": id})
		if _, err := net.Dial("tcp", address); err == nil {
			t.Fatal("deleted inbound still listening")
		}
	})

	t.Run("gateway", func(t *testing.T) {
		workspace := call(t, session, "get_gateway", map[string]any{})
		conforms(t, session, "save_gateway", workspace)
		workspace["gateways"] = []any{map[string]any{"id": "gw", "name": "Test gateway", "enabled": true, "debug": false, "revision": 0,
			"policies": []any{}, "backendPools": []any{}, "filters": []any{}, "maxBodyBytes": 0,
			"fallback": map[string]any{"type": "block", "status": 204, "preserveHost": false, "outbound": map[string]any{}, "rewrite": map[string]any{}}}}
		saved := call(t, session, "save_gateway", workspace)
		if gateways, _ := saved["gateways"].([]any); len(gateways) != 1 {
			t.Fatalf("gateway = %v", saved)
		}
		result := call(t, session, "test_gateway", map[string]any{"gatewayId": "gw", "url": "https://example.com/", "method": "GET", "inboundId": "", "headers": map[string]any{}})
		if action, _ := result["action"].(map[string]any); action["type"] != "block" {
			t.Fatalf("gateway test = %v", result)
		}
		call(t, session, "get_gateway_status", map[string]any{})
	})

	t.Run("lists and rules", func(t *testing.T) {
		list := call(t, session, "create_route_list", map[string]any{"id": "ads", "name": "Ads", "type": "host", "source": map[string]any{"type": "local", "local": map[string]any{"lists": []any{"ads.example"}}}})
		if list["id"] != "ads" {
			t.Fatalf("list = %v", list)
		}
		got := call(t, session, "get_route_list", map[string]any{"id": "ads"})
		conforms(t, session, "create_route_list", got)
		got["source"].(map[string]any)["local"] = map[string]any{"lists": []any{"ads.example", "tracker.example"}}
		got["id"] = "ads"
		call(t, session, "update_route_list", got)
		rule := call(t, session, "create_route_rule", map[string]any{"rule": map[string]any{"id": "block-ads", "name": "Block ads", "mode": "block", "revision": 0,
			"rules": []any{map[string]any{"type": "host", "host": map[string]any{"list": "ads"}}}}})
		if rule["rule"].(map[string]any)["revision"] != float64(1) {
			t.Fatalf("rule = %v", rule)
		}
		got = call(t, session, "get_route_rule", map[string]any{"id": "block-ads"})
		conforms(t, session, "create_route_rule", got)
		got["id"] = "block-ads"
		got["rule"].(map[string]any)["name"] = "Block ads and trackers"
		if updated := call(t, session, "update_route_rule", got); updated["rule"].(map[string]any)["name"] != "Block ads and trackers" {
			t.Fatalf("update = %v", updated)
		}
		call(t, session, "apply_routes", map[string]any{})
		if f.routes.applied != 1 {
			t.Fatal("routing was not applied")
		}
		if tested := call(t, session, "test_route", map[string]any{"host": "ads.example"}); tested["afterAddr"] != "ads.example" {
			t.Fatalf("route test = %v", tested)
		}
		if lists := call(t, session, "list_route_lists", map[string]any{}); !strings.Contains(mustJSON(lists), `"ads"`) {
			t.Fatalf("lists = %v", lists)
		}
		call(t, session, "delete_route_rule", map[string]any{"id": "block-ads"})
		call(t, session, "delete_route_list", map[string]any{"id": "ads"})
	})

	t.Run("dns and hosts", func(t *testing.T) {
		resolver := call(t, session, "save_resolver", map[string]any{"name": "Quad9", "type": "doh", "host": "https://dns.quad9.net/dns-query"})
		id := resolver["id"].(string)
		got := call(t, session, "get_resolver", map[string]any{"id": id})
		conforms(t, session, "save_resolver", got)
		if answer := call(t, session, "test_resolver", map[string]any{"resolver": got, "domain": "example.com", "queryType": "A"}); answer["domain"] != "example.com" {
			t.Fatalf("resolver test = %v", answer)
		}
		call(t, session, "delete_resolver", map[string]any{"id": id})

		call(t, session, "add_host", map[string]any{"host": "nas.home", "target": "192.168.1.10"})
		if _, isError, _ := callText(t, session, "add_host", map[string]any{"host": "nas.home", "target": "192.168.1.11"}); !isError {
			t.Fatal("duplicate host accepted")
		}
		call(t, session, "update_host", map[string]any{"host": "nas.home", "target": "192.168.1.11"})
		if hosts := call(t, session, "list_hosts", map[string]any{}); !strings.Contains(mustJSON(hosts), "192.168.1.11") {
			t.Fatalf("hosts = %v", hosts)
		}
		call(t, session, "delete_host", map[string]any{"host": "nas.home"})
	})

	t.Run("arguments are validated", func(t *testing.T) {
		for tool, arguments := range map[string]any{
			"save_node":   map[string]any{"name": "x", "unknownField": true},
			"add_host":    map[string]any{"host": "bad host", "target": "1.1.1.1"},
			"delete_node": map[string]any{},
			"test_route":  map[string]any{"host": ""},
		} {
			if text, isError, err := callText(t, session, tool, arguments); err == nil && !isError {
				t.Errorf("%s accepted %v: %s", tool, arguments, text)
			}
		}
	})
}

// Configuration tools follow the granted scopes like every other tool.
func TestMCPConfigurationToolsNeedWritePermissions(t *testing.T) {
	f := newMCPConfigFixture(t)
	access, _ := f.authorize(f.admin, "mcp:connect nodes:read routes:read resolver:read")
	session, err := f.connect(t.Context(), access)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	names := toolNames(t, session)
	for _, want := range []string{"get_node", "list_route_lists", "get_route_rule", "test_route", "get_resolver", "list_hosts"} {
		if !contains(names, want) {
			t.Errorf("missing read tool %s in %v", want, names)
		}
	}
	for _, denied := range []string{"save_node", "import_nodes", "delete_node", "test_node_latency", "create_route_rule", "apply_routes", "save_resolver", "add_host", "save_inbound", "save_gateway", "test_gateway"} {
		if contains(names, denied) {
			t.Errorf("write tool %s listed without its permission", denied)
		}
		if _, isError, err := callText(t, session, denied, map[string]any{}); err == nil && !isError {
			t.Errorf("%s ran without its permission", denied)
		}
	}
}

func contains(items []string, item string) bool {
	return slices.Contains(items, item)
}

func mustJSON(value any) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
