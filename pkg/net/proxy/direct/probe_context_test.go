package direct

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type cancellableProbeResolver struct{}

func (cancellableProbeResolver) LookupIP(ctx context.Context, _ string, _ ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (cancellableProbeResolver) Raw(context.Context, netapi.DNSQuestion) (*dns.Msg, error) {
	return nil, errors.ErrUnsupported
}
func (cancellableProbeResolver) Name() string { return "probe-test" }
func (cancellableProbeResolver) Close() error { return nil }
func TestContextPacketWriteCancelsEndpointDNS(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := &UDPPacketConn{resolver: new(netapi.ResolverOptions).SetResolver(cancellableProbeResolver{})}
		addr, _ := netapi.ParseAddress("udp", "probe.example.invalid:53")
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err := p.WriteToContext(ctx, []byte("probe"), addr)
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) != 100*time.Millisecond {
			t.Fatal("probe DNS escaped cancellation", err, time.Since(start))
		}
		// The absent underlying socket would panic if a cancelled write reached it.
		if _, err := p.WriteToContext(ctx, []byte("cancelled"), addr); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	})
}
