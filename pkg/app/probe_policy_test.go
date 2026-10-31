package app

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
	"github.com/Asutorufa/yuhaiin/pkg/node"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

// Start owns global DNS/metrics/network monitors. A subprocess exercises the
// actual startup without sharing those globals with unrelated parallel tests.
func TestApplicationProbePolicyStartupAndRecovery(t *testing.T) {
	const marker = "YUH_CONTRACT_PROBE_POLICY_CHILD"
	if os.Getenv(marker) != "1" {
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestApplicationProbePolicyStartupAndRecovery$", "-test.v")
		cmd.Env = append(os.Environ(), marker+"=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("application probe policy: %v\n%s", err, output)
		}
		return
	}
	dir := t.TempDir()
	db, err := storagesqlite.Open(t.Context(), paths.PathGenerator.State(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := plainstore.NewInboundStore(db.DB()).TrafficControl(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().ExecContext(t.Context(), `INSERT INTO inbound_traffic_control(id,config_json) VALUES(1,'{"enabled":true,"defaultProfile":"missing"}')`); err != nil {
		t.Fatal(err)
	}
	rules := plainstore.NewRouteRuleStore(db.DB())
	rule := contractroute.RouteRule{ID: "probe-policy", Name: "Probe policy", Mode: "block", Rules: []contractroute.RuleExpr{{Type: "always", Always: &contractroute.MatchAllExpr{}}}}
	if err := rules.SaveRule(t.Context(), rule, 1, 0); err != nil {
		t.Fatal(err)
	}
	runtime, err := Start(&StartOptions{Context: t.Context(), ConfigPath: dir, StateStore: testStateStore{db: db.DB()}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := runtime.Close(); err != nil {
			pending := []error{err}
			for len(pending) > 0 {
				e := pending[len(pending)-1]
				pending = pending[:len(pending)-1]
				if joined, ok := e.(interface{ Unwrap() []error }); ok {
					pending = append(pending, joined.Unwrap()...)
					continue
				}
				if strings.HasPrefix(e.Error(), "nftables close error:") && errors.Is(e, syscall.EPERM) {
					t.Log("nftables cleanup requires CAP_NET_ADMIN; probe/routing/shaping checks completed without that capability")
					continue
				}
				t.Error(e)
			}
		}
	}()
	if _, err := runtime.NodeRuntime.Save(t.Context(), contractnode.Node{ID: "a", Name: "Fixed candidate", Enabled: true, Chain: []contractnode.Protocol{{Type: "direct", Direct: &contractnode.Direct{}}}}); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	request := contractnode.LatencyRequest{Type: "tcp_connect", Host: listener.Addr().String()}
	status, err := runtime.NodeRuntime.Monitoring(t.Context())
	if err != nil || status.PolicyState != "waiting" {
		t.Fatal("invalid QoS did not gate measurements", status, err)
	}
	if _, err := runtime.NodeRuntime.Latency(t.Context(), "a", request); err == nil {
		t.Fatal("uninitialized traffic policy admitted a probe")
	}
	cfgStore := inbound.NewContractStore(plainstore.NewInboundStore(db.DB()), runtime.Inbound)
	if err := cfgStore.SaveTrafficControl(t.Context(), trafficcontrol.Config{}); err != nil {
		t.Fatal(err)
	}
	status, err = runtime.NodeRuntime.Monitoring(t.Context())
	if err != nil || status.PolicyState != "enforced" {
		t.Fatal("fixed QoS did not resume measurements", status, err)
	}
	if _, err := runtime.NodeRuntime.Latency(t.Context(), "a", request); !netapi.IsBlockError(err) {
		t.Fatal("routing block was bypassed", err)
	}
	selector, err := node.NewSelectorService(runtime.NodeRuntime).Save(t.Context(), contractnode.Selector{Name: "Unknown automatic route", NodeID: "a", Policy: &contractnode.SelectorPolicy{Mode: "failover", Candidates: []contractnode.SelectorCandidate{{NodeID: "a", Enabled: true, Weight: 1}}}})
	if err != nil {
		t.Fatal(err)
	}
	rule.Mode = "proxy"
	rule.Target = contractroute.Target{Type: "selector", ID: selector.ID}
	if err := rules.SaveRule(t.Context(), rule, 1, 0); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Rules.Apply(t.Context()); err != nil {
		t.Fatal(err)
	}
	result, err := runtime.NodeRuntime.Latency(t.Context(), "a", request)
	if err != nil || !result.OK {
		t.Fatal("probe entered its own unready automatic route instead of fixed Node", result, err)
	}
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal("fixed Node never connected to the real test endpoint", err)
	}
	_ = conn.Close()
	if runtime.Inbound.TrafficControlStatus().Global.Sessions != 0 {
		t.Fatal("completed probe leaked session admission")
	}
}
