package l2tp

import (
	"context"
	"errors"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"net"
	"testing"
)

type refusingUpstream struct {
	netapi.EmptyDispatch
	calls int
}

func (p *refusingUpstream) PacketConn(context.Context, netapi.Address) (net.PacketConn, error) {
	p.calls++
	return nil, errors.ErrUnsupported
}
func (p *refusingUpstream) Conn(context.Context, netapi.Address) (net.Conn, error) {
	return nil, errors.ErrUnsupported
}
func (p *refusingUpstream) Ping(context.Context, netapi.Address) (uint64, error) {
	return 0, errors.ErrUnsupported
}
func (p *refusingUpstream) Close() error { return nil }
func TestTransportHonorsUpstreamAndValidatesBeforeDial(t *testing.T) {
	upstream := new(refusingUpstream)
	_, err := NewClient(Config{Version: 2, Gateway: "127.0.0.1:1701"}, upstream)
	if !errors.Is(err, errors.ErrUnsupported) || upstream.calls != 1 {
		t.Fatalf("bypassed failing upstream: %v, calls %d", err, upstream.calls)
	}
	for _, cfg := range []Config{
		{Version: 2, Gateway: ":1701"}, {Version: 2, Gateway: "127.0.0.1:0"}, {Version: 2, Gateway: "127.0.0.1:1701", AuthType: "unknown"},
		{Version: 3, Gateway: "127.0.0.1:1701"}, {Version: 3, Gateway: "127.0.0.1:1701", Static: true, Address: "10.1.0.2/24"},
		{Version: 3, Gateway: "127.0.0.1:1701", Address: "fd88::2/64"}, {Version: 3, Gateway: "127.0.0.1:1701", Address: "10.1.0.2/24", LocalCookie: []byte{1}},
		{Version: 2, Gateway: "127.0.0.1:1701", MTU: 1000, IPv6Address: "fd88::2/64"},
	} {
		c, err := NewClient(cfg, upstream)
		if c != nil {
			_ = c.Close()
		}
		if err == nil || upstream.calls != 1 {
			t.Fatalf("dialed invalid config %+v: %v, calls %d", cfg, err, upstream.calls)
		}
	}
}
