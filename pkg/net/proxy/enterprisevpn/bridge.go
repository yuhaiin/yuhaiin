// Package enterprisevpn adapts four in-process VPN protocol engines to the
// existing yuhaiin gVisor IP stack, without installing any host network routes.
package enterprisevpn

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	"github.com/xen0bit/veepin/client"
)

// packetBridge is a one-shot, packet-oriented TUN used by the vendored
// protocol engines. Read may start before IP configuration arrives; it blocks
// until Attach, instead of losing packets or inventing an IP address.
type packetBridge struct {
	mu      sync.Mutex
	ready   chan struct{}
	once    sync.Once
	network *wireguard.NetTun
	closed  bool
}

func newPacketBridge() *packetBridge {
	return &packetBridge{ready: make(chan struct{})}
}
func (b *packetBridge) Attach(cfg client.Result) (*wireguard.NetTun, error) {
	if cfg.Layer2 {
		return nil, errors.New("enterprisevpn: layer 2 tunnels are unsupported")
	}
	var prefixes []netip.Prefix
	for _, addr := range []struct {
		ip   net.IP
		bits int
	}{
		{cfg.AssignedIP, ipv4Bits(cfg.Netmask)},
		{cfg.AssignedIP6, cfg.Prefix6},
	} {
		if addr.ip == nil {
			continue
		}
		ip, ok := netip.AddrFromSlice(addr.ip)
		if !ok {
			return nil, errors.New("enterprisevpn: invalid assigned IP")
		}
		ip = ip.Unmap()
		bits := addr.bits
		if bits <= 0 {
			bits = ip.BitLen()
		}
		if bits > ip.BitLen() {
			return nil, errors.New("enterprisevpn: invalid address prefix")
		}
		prefixes = append(prefixes, netip.PrefixFrom(ip, bits))
	}
	if len(prefixes) == 0 {
		return nil, errors.New("enterprisevpn: VPN server did not assign an address")
	}
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = 1400
	}
	if mtu < 576 || mtu > 9000 {
		return nil, fmt.Errorf("enterprisevpn: unsafe MTU %d", mtu)
	}
	network, err := wireguard.CreateNetTUN(prefixes, mtu)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.network != nil {
		_ = network.Close()
		return nil, io.ErrClosedPipe
	}
	b.network = network
	b.once.Do(func() { close(b.ready) })
	return network, nil
}
func ipv4Bits(mask net.IPMask) int {
	if len(mask) == 0 {
		return 0
	}
	ones, bits := mask.Size()
	if bits != 32 {
		return 0
	}
	return ones
}
func (b *packetBridge) await() (*wireguard.NetTun, error) {
	<-b.ready
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.network == nil {
		return nil, io.ErrClosedPipe
	}
	return b.network, nil
}
func (b *packetBridge) Read(p []byte) (int, error) {
	n, err := b.await()
	if err != nil {
		return 0, err
	}
	return n.ReadPacket(p)
}
func (b *packetBridge) Write(p []byte) (int, error) {
	n, err := b.await()
	if err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	if _, err := n.Write([][]byte{p}, 0); err != nil {
		return 0, err
	}
	return len(p), nil
}
func (b *packetBridge) Close() error {
	b.mu.Lock()
	b.closed = true
	n := b.network
	b.once.Do(func() { close(b.ready) })
	b.mu.Unlock()
	if n != nil {
		return n.Close()
	}
	return nil
}
