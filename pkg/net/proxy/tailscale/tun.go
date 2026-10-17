package tailscale

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	"github.com/tailscale/wireguard-go/tun"
)

// tailnetTun lets tsnet own authentication, route/ACL updates and encrypted
// packet transport while our stack owns application TCP/UDP. Addresses arrive
// after Up; packet reads may start earlier and must wait without inventing IPs.
type tailnetTun struct {
	mu      sync.Mutex
	ready   chan struct{}
	events  chan tun.Event
	network *wireguard.LightweightNetTun
	closed  bool
	metrics sync.Once
	v4, v6  netip.Addr
}

func newTailnetTun() *tailnetTun {
	n := &tailnetTun{ready: make(chan struct{}), events: make(chan tun.Event, 1)}
	n.events <- tun.EventUp
	return n
}
func (n *tailnetTun) configure(v4, v6 netip.Addr) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return net.ErrClosed
	}
	if n.network != nil {
		// A changed tailnet identity must reconnect, rather than silently using the
		// old source address or taking existing sockets onto a different identity.
		if n.v4 != v4 || n.v6 != v6 {
			return errors.New("tailscale: assigned addresses changed; reconnect the node")
		}
		return nil
	}
	var addresses []netip.Prefix
	for _, ip := range []netip.Addr{v4, v6} {
		if ip.IsValid() {
			addresses = append(addresses, netip.PrefixFrom(ip, ip.BitLen()))
		}
	}
	if len(addresses) == 0 {
		return errors.New("tailscale: no assigned tunnel addresses")
	}
	network, err := wireguard.CreateLightweightNetTUN(addresses, 1280)
	if err != nil {
		return err
	}
	n.network = network
	n.v4, n.v6 = v4, v6
	close(n.ready)
	return nil
}
func (n *tailnetTun) await() (*wireguard.LightweightNetTun, error) {
	<-n.ready
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil, net.ErrClosed
	}
	return n.network, nil
}
func (*tailnetTun) Name() (string, error)      { return "lightweight-tailnet", nil }
func (*tailnetTun) File() *os.File             { return nil }
func (*tailnetTun) MTU() (int, error)          { return 1280, nil }
func (*tailnetTun) BatchSize() int             { return 1 }
func (n *tailnetTun) Events() <-chan tun.Event { return n.events }
func (n *tailnetTun) Read(b []byte, p []tun.ReadPacket) (int, error) {
	s, err := n.await()
	if err != nil {
		return 0, err
	}
	return s.Read(b, p)
}
func (n *tailnetTun) Write(b [][]byte, offset int) (int, error) {
	s, err := n.await()
	if err != nil {
		return 0, err
	}
	return s.Write(b, offset)
}
func (n *tailnetTun) Close() error {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return nil
	}
	n.closed = true
	network := n.network
	if network == nil {
		close(n.ready)
	}
	close(n.events)
	n.mu.Unlock()
	if network != nil {
		return network.Close()
	}
	return nil
}
