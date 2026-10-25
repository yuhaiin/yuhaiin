package latency

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type cancellableProbeProxy struct {
	netapi.Proxy
	started chan struct{}
}

func (p *cancellableProbeProxy) Conn(ctx context.Context, _ netapi.Address) (net.Conn, error) {
	select {
	case p.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}
func (p *cancellableProbeProxy) PacketConn(ctx context.Context, _ netapi.Address) (net.PacketConn, error) {
	select {
	case p.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestProbeCancellationReachesActualNodeTransport(t *testing.T) {
	for _, kind := range []string{"http", "tcp", "dns", "udp", "doq", "stun", "stun_tcp"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			p := &cancellableProbeProxy{started: make(chan struct{}, 1)}
			done := make(chan error, 1)
			go func() {
				_, err := LatencyWithContext(ctx, contract.LatencyRequest{Type: kind, URL: "https://target.invalid", Host: "127.0.0.1:53", TargetDomain: "target.invalid"}, p, LatencyOptions{})
				done <- err
			}()
			select {
			case <-p.started:
			case <-time.After(time.Second):
				t.Fatal("probe never reached target node")
			}
			cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("canceled probe succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("probe ignored cancellation")
			}
		})
	}
}

func TestAlreadyCancelledProbeNeverStartsTransport(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	p := &cancellableProbeProxy{started: make(chan struct{}, 1)}
	if _, err := LatencyWithContext(ctx, contract.LatencyRequest{Type: "http"}, p, LatencyOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	select {
	case <-p.started:
		t.Fatal("cancelled probe dialed")
	default:
	}
}
