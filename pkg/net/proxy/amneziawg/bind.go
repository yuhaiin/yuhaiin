package amneziawg

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	awgconn "github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

type endpoint struct{ addr netip.AddrPort }

var _ awgconn.Endpoint = endpoint{}

func (e endpoint) ClearSrc()           {}
func (e endpoint) SrcToString() string { return "" }
func (e endpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e endpoint) DstToString() string { return e.addr.String() }
func (e endpoint) DstToBytes() []byte  { b, _ := e.addr.MarshalBinary(); return b }
func (e endpoint) DstIP() netip.Addr   { return e.addr.Addr() }

type socketBind struct {
	mu       sync.Mutex
	pc       net.PacketConn
	upstream netapi.Proxy
	peer     string
}

var _ awgconn.Bind = (*socketBind)(nil)

func newSocketBind(upstream netapi.Proxy, peer string) *socketBind {
	return &socketBind{upstream: upstream, peer: peer}
}
func (b *socketBind) BatchSize() int       { return 1 }
func (b *socketBind) SetMark(uint32) error { return nil }
func (b *socketBind) ParseEndpoint(s string) (awgconn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err == nil {
		return endpoint{ap}, nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	ips, err := netapi.Bootstrap().LookupIP(context.Background(), host)
	if err != nil {
		return nil, err
	}
	addr, ok := netip.AddrFromSlice(ips.PreferAAAA())
	if !ok {
		return nil, fmt.Errorf("amneziawg: no address for %q", host)
	}
	ap, err = netip.ParseAddrPort(net.JoinHostPort(addr.Unmap().String(), port))
	if err != nil {
		return nil, err
	}
	return endpoint{ap}, nil
}
func (b *socketBind) Open(port uint16) ([]awgconn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pc != nil {
		return nil, 0, awgconn.ErrBindAlreadyOpen
	}
	var pc net.PacketConn
	var err error
	if b.upstream != nil && !register.IsZero(b.upstream) {
		addr, e := netapi.ParseAddress("udp", b.peer)
		if e != nil {
			return nil, 0, e
		}
		pc, err = b.upstream.PacketConn(context.Background(), addr)
	} else {
		// Use yuhaiin's own listener instead of an independent net.ListenPacket.
		pc, err = dialer.ListenPacket(context.Background(), "udp", "")
	}
	if err != nil {
		return nil, 0, err
	}
	b.pc = pc
	var localPort uint16
	if addr, ok := pc.LocalAddr().(*net.UDPAddr); ok && addr.Port > 0 && addr.Port <= 65535 {
		localPort = uint16(addr.Port)
	}
	fn := func(bufs [][]byte, sizes []int, eps []awgconn.Endpoint) (int, error) {
		if len(bufs) == 0 || len(sizes) == 0 || len(eps) == 0 {
			return 0, io.ErrShortBuffer
		}
		n, src, err := pc.ReadFrom(bufs[0])
		if err != nil {
			return 0, err
		}
		a, e := netapi.ParseSysAddr(src)
		if e != nil {
			return 0, e
		}
		ap, er := netip.ParseAddrPort(a.String())
		if er != nil {
			return 0, er
		}
		sizes[0] = n
		eps[0] = endpoint{ap}
		return 1, nil
	}
	return []awgconn.ReceiveFunc{fn}, localPort, nil
}
func (b *socketBind) Send(bufs [][]byte, e awgconn.Endpoint) error {
	ep, ok := e.(endpoint)
	if !ok {
		return awgconn.ErrWrongEndpointType
	}
	b.mu.Lock()
	pc := b.pc
	b.mu.Unlock()
	if pc == nil {
		return net.ErrClosed
	}
	to := net.UDPAddrFromAddrPort(ep.addr)
	for _, buf := range bufs {
		n, err := pc.WriteTo(buf, to)
		if err != nil {
			return err
		}
		if n != len(buf) {
			return io.ErrShortWrite
		}
	}
	return nil
}
func (b *socketBind) Close() error {
	b.mu.Lock()
	pc := b.pc
	b.pc = nil
	b.mu.Unlock()
	if pc == nil {
		return nil
	}
	err := pc.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
