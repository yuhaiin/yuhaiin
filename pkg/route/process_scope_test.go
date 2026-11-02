package route

import (
	"errors"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type scopedTestDumper struct {
	process netapi.Process
	err     error
	calls   int
}

func (d *scopedTestDumper) ProcessName(string, netapi.Address, netapi.Address) (netapi.Process, error) {
	d.calls++
	return d.process, d.err
}

func processScopeRoute(t *testing.T, mode string) (*Route, *scopedTestDumper) {
	t.Helper()
	old := configuration.ProcessLookupMode.Load()
	configuration.ProcessLookupMode.Store(mode)
	t.Cleanup(func() { configuration.ProcessLookupMode.Store(old) })
	matchers := newTestMatchers(t)
	matchers.list.lists = staticRouteListBook{detail: contract.RouteListDetail{ID: "ssh-tools", Name: "ssh-tools", Type: "process",
		Source: contract.ListSource{Type: "local", Local: &contract.LocalSource{Lists: []string{"/usr/bin/curl"}}}}}
	if err := matchers.Update(
		contract.RouteRule{ID: "ssh-tool", Name: "ssh-tool", Mode: "direct", Target: contract.Target{},
			Rules: []contract.RuleExpr{{Type: "process", Process: &contract.ListRef{List: "ssh-tools"}}}},
		alwaysRule("fallback", "proxy", contract.Target{}),
	); err != nil {
		t.Fatal(err)
	}
	router := NewRoute(new(gatewayTestDialer), staticResolverBook{resolver: staticResolver{}}, matchers.list, nil)
	router.ms = matchers
	router.ms.list.ProcessTrie().Add("/usr/bin/curl", "ssh-tools")
	// The host dumper reports the same path, so a fallback would be visible.
	host := &scopedTestDumper{process: netapi.Process{Path: "/usr/bin/curl", Pid: 1, Uid: 0}}
	router.ProcessDumper = host
	return router, host
}

func processScopeContext(t *testing.T, scope netapi.ProcessDumper) (*netapi.Context, netapi.Address) {
	t.Helper()
	ctx := netapi.WithContext(t.Context())
	source, _ := netapi.ParseAddress("tcp", "172.31.254.2:40000")
	destination, _ := netapi.ParseAddress("tcp", "192.0.2.1:443")
	ctx.Source, ctx.Destination = source, destination
	ctx.SetProcessScope(scope)
	return ctx, destination
}

func TestRouteMatchesProcessInsideScope(t *testing.T) {
	router, host := processScopeRoute(t, "always")
	scope := &scopedTestDumper{process: netapi.Process{Path: "/usr/bin/curl", Pid: 4242, Uid: 65534}}
	ctx, destination := processScopeContext(t, scope)
	if _, _, err := router.ResolveTCP(ctx, destination, contract.Target{}); err != nil {
		t.Fatal(err)
	}
	if scope.calls == 0 || host.calls != 0 {
		t.Fatalf("scope lookups=%d host lookups=%d", scope.calls, host.calls)
	}
	if path, pid, uid := ctx.GetProcess(); path != "/usr/bin/curl" || pid != 4242 || uid != 65534 {
		t.Fatalf("recorded process %q pid=%d uid=%d", path, pid, uid)
	}
	if _, name := ctx.MatchedRule(); name != "ssh-tool" {
		t.Fatalf("matched rule %q, want ssh-tool", name)
	}
	history := ctx.MatchHistory()
	if len(history) == 0 || history[0].RuleName != "ssh-tool" {
		t.Fatalf("match history did not record the process rule: %#v", history)
	}
}

func TestRouteScopedLookupFailureNeverUsesHost(t *testing.T) {
	router, host := processScopeRoute(t, "always")
	scope := &scopedTestDumper{err: errors.New("socket not found")}
	ctx, destination := processScopeContext(t, scope)
	if _, _, err := router.ResolveTCP(ctx, destination, contract.Target{}); err != nil {
		t.Fatal(err)
	}
	if scope.calls == 0 || host.calls != 0 {
		t.Fatalf("scope lookups=%d host lookups=%d", scope.calls, host.calls)
	}
	if path, _, _ := ctx.GetProcess(); path != "" {
		t.Fatalf("unknown process was attributed to %q", path)
	}
	if _, name := ctx.MatchedRule(); name != "fallback" {
		t.Fatalf("matched rule %q, want fallback", name)
	}
}

func TestRouteScopedLookupHonorsLookupMode(t *testing.T) {
	router, _ := processScopeRoute(t, "off")
	scope := &scopedTestDumper{process: netapi.Process{Path: "/usr/bin/curl", Pid: 4242}}
	ctx, destination := processScopeContext(t, scope)
	if _, _, err := router.ResolveTCP(ctx, destination, contract.Target{}); err != nil {
		t.Fatal(err)
	}
	if scope.calls != 0 {
		t.Fatalf("lookup mode off still queried the scope %d times", scope.calls)
	}
}

func TestRouteHostLookupWithoutScope(t *testing.T) {
	router, host := processScopeRoute(t, "always")
	ctx, destination := processScopeContext(t, nil)
	if _, _, err := router.ResolveTCP(ctx, destination, contract.Target{}); err != nil {
		t.Fatal(err)
	}
	if host.calls == 0 {
		t.Fatal("host flows no longer use the host process dumper")
	}
}
