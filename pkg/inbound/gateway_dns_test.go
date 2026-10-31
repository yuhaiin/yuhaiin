package inbound

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type gatewayLoopbackResolver struct{ netapi.ErrorResolver }

func (gatewayLoopbackResolver) LookupIP(context.Context, string, ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
	return &netapi.IPs{A: []net.IP{net.IPv4(127, 0, 0, 1)}}, nil
}

func (gatewayLoopbackResolver) Name() string { return "gateway-loopback-fixture" }

type gatewayBlockedBootstrap struct {
	gatewayLoopbackResolver
	blocked *atomic.Bool
}

func (r gatewayBlockedBootstrap) LookupIP(ctx context.Context, domain string, opts ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
	if r.blocked.Load() && strings.TrimSuffix(domain, ".") == "app.example" {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return r.gatewayLoopbackResolver.LookupIP(ctx, domain, opts...)
}

// A subprocess confines the deliberately unavailable global Bootstrap to this
// fixture. The original routing assertions and three-second client deadline are
// unchanged, and must pass even when unrelated global DNS cannot answer.
func TestGatewayRoutingDoesNotDependOnGlobalBootstrap(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestExistingRouteGatesHTTPAndMITMStreams$", "-test.count=1", "-test.timeout=10s")
	command.Env = append(os.Environ(), "YUHAIIN_TEST_GATEWAY_BLOCK_BOOTSTRAP=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("routing fixture depended on global DNS: %v\n%s", err, output)
	}
}
