package wireguard

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight"
	"github.com/tailscale/wireguard-go/tun"
)

// LightweightNetTun connects the shared BBR v3 lightweight IP stack to a VPN's
// packet interface.
type LightweightNetTun struct {
	stack        *lightweight.Stack
	link         *packetLink
	events       chan tun.Event
	mtu          int
	hasV4, hasV6 bool
	closeOnce    sync.Once
	closeErr     error
}

func CreateLightweightNetTUN(localAddresses []netip.Prefix, mtu int) (*LightweightNetTun, error) {
	return createLightweightNetTUN(localAddresses, mtu, false, "")
}

// CreateLightweightNetTUNWithCongestionControl overrides the RemoteTunnel profile's
// default congestion control for controlled interoperability testing.
func CreateLightweightNetTUNWithCongestionControl(localAddresses []netip.Prefix, mtu int, algorithm string) (*LightweightNetTun, error) {
	return createLightweightNetTUN(localAddresses, mtu, false, algorithm)
}

// CreateLightweightInboundTUN terminates arbitrary routed client destinations
// entirely in the in-memory lightweight TCP/IP stack. It never opens a system TUN.
func CreateLightweightInboundTUN(localAddresses []netip.Prefix, mtu int) (*LightweightNetTun, error) {
	return createLightweightNetTUN(localAddresses, mtu, true, "")
}

func createLightweightNetTUN(localAddresses []netip.Prefix, mtu int, inbound bool, algorithm string) (*LightweightNetTun, error) {
	if mtu == 0 {
		mtu = 1500
	}
	dev := &LightweightNetTun{link: newPacketLink(), events: make(chan tun.Event, 1), mtu: mtu}
	addresses := make([]netip.Addr, 0, len(localAddresses))
	for _, prefix := range localAddresses {
		if !prefix.IsValid() {
			return nil, errors.New("wireguard: invalid local address")
		}
		ip := prefix.Addr().Unmap()
		addresses = append(addresses, ip)
		dev.hasV4 = dev.hasV4 || ip.Is4()
		dev.hasV6 = dev.hasV6 || ip.Is6()
	}
	var err error
	dev.stack, err = lightweight.New(lightweight.Config{Addresses: addresses, MTU: mtu, Profile: lightweight.RemoteTunnel, Promiscuous: inbound, ForwardUDP: inbound, CongestionControl: algorithm}, dev.link)
	if err != nil {
		_ = dev.link.Close()
		return nil, err
	}
	dev.events <- tun.EventUp
	return dev, nil
}

// Stack is the already-running userspace protocol stack behind this packet link.
func (n *LightweightNetTun) Stack() *lightweight.Stack { return n.stack }

func (n *LightweightNetTun) Name() (string, error)    { return "lightweight", nil }
func (n *LightweightNetTun) File() *os.File           { return nil }
func (n *LightweightNetTun) Events() <-chan tun.Event { return n.events }
func (n *LightweightNetTun) BatchSize() int           { return 1 }

func (n *LightweightNetTun) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	if len(packets) == 0 || len(slab) < 2*tun.ReadPacketSpacing {
		return 0, tun.ErrTooManySegments
	}
	size, err := n.ReadPacket(slab[tun.ReadPacketSpacing : len(slab)-tun.ReadPacketSpacing])
	if errors.Is(err, io.ErrShortBuffer) {
		return 0, tun.ErrTooManySegments
	}
	if err != nil {
		return 0, err
	}
	packets[0] = tun.ReadPacket{Offset: tun.ReadPacketSpacing, Size: size}
	return 1, nil
}

func (n *LightweightNetTun) Write(buffers [][]byte, offset int) (int, error) {
	for _, b := range buffers {
		if offset < 0 || offset > len(b) {
			return 0, io.ErrShortBuffer
		}
	}
	count := 0
	for _, b := range buffers {
		if len(b) == offset {
			continue
		}
		if err := n.link.fromEngine.write(b[offset:]); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

// InjectPacket delivers one decrypted IP packet into the lightweight stack.
// Unlike Write (the WireGuard TUN interface), this flows from the tunnel engine
// toward local TCP/UDP sockets, rather than from sockets toward the engine.
func (n *LightweightNetTun) InjectPacket(b []byte) error { return n.link.fromEngine.write(b) }

// ReadPacket bridges the incompatible TUN APIs of different WireGuard engines.
func (n *LightweightNetTun) ReadPacket(b []byte) (int, error) { return n.link.toEngine.read(b) }
func (n *LightweightNetTun) Flush() error                     { return nil }
func (n *LightweightNetTun) MTU() (int, error)                { return n.mtu, nil }
func (n *LightweightNetTun) HasV4() bool                      { return n.hasV4 }
func (n *LightweightNetTun) HasV6() bool                      { return n.hasV6 }
func (n *LightweightNetTun) Close() error {
	n.closeOnce.Do(func() { n.closeErr = n.stack.Close(); close(n.events) })
	return n.closeErr
}

func (n *LightweightNetTun) DialContextTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error) {
	if addr == nil {
		return nil, errors.New("wireguard: nil TCP destination")
	}
	ap := addr.AddrPort()
	return n.stack.DialContextTCP(ctx, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
}

func (n *LightweightNetTun) ListenTCP(addr *net.TCPAddr) (*lightweight.TCPListener, error) {
	if addr == nil || len(addr.IP) == 0 {
		port := 0
		if addr != nil {
			port = addr.Port
		}
		if port < 0 || port > 65535 {
			return nil, errors.New("wireguard: invalid TCP port")
		}
		if n.hasV6 {
			return n.stack.ListenDualTCP(uint16(port))
		}
		return n.stack.ListenTCP(netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(port)))
	}
	ap := addr.AddrPort()
	return n.stack.ListenTCP(netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
}

func (n *LightweightNetTun) DialUDP(local, remote *net.UDPAddr) (*lightweight.UDPConn, error) {
	var la, ra netip.AddrPort
	if remote != nil {
		ra = remote.AddrPort()
		ra = netip.AddrPortFrom(ra.Addr().Unmap(), ra.Port())
		if !ra.IsValid() {
			return nil, errors.New("wireguard: invalid UDP destination")
		}
	}
	if local != nil && len(local.IP) > 0 {
		la = local.AddrPort()
		la = netip.AddrPortFrom(la.Addr().Unmap(), la.Port())
		if !la.IsValid() {
			return nil, errors.New("wireguard: invalid UDP source")
		}
	}
	if !la.IsValid() && !ra.IsValid() {
		port := 0
		if local != nil {
			port = local.Port
		}
		if port < 0 || port > 65535 {
			return nil, errors.New("wireguard: invalid UDP port")
		}
		if n.hasV6 {
			return n.stack.ListenDualUDP(uint16(port))
		}
		return n.stack.ListenUDP(netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(port)))
	}
	if !la.IsValid() && local != nil {
		if local.Port < 0 || local.Port > 65535 {
			return nil, errors.New("wireguard: invalid UDP port")
		}
		ip := netip.IPv6Unspecified()
		if ra.Addr().Is4() {
			ip = netip.IPv4Unspecified()
		}
		la = netip.AddrPortFrom(ip, uint16(local.Port))
	}
	return n.stack.DialUDP(la, ra)
}
