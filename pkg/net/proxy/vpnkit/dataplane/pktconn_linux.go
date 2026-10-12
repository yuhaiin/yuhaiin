//go:build linux

package dataplane

// Replying from the address a packet arrived on.
//
// Every UDP server here binds the wildcard by default, which is what you want:
// one socket serving whatever addresses the host has. The problem is the reply.
// A socket bound to 0.0.0.0 has no source address of its own, so the kernel
// picks one by route lookup at send time — and on a multi-homed host that is
// frequently not the address the client sent to. The client sees a reply from an
// address it never contacted and drops it.
//
// Every protocol in this tree is affected, and none of the tests can see it: the
// interop matrix runs on single-homed containers, where the route lookup picks
// the only address there is. It stays invisible until someone deploys on a host
// with two interfaces, where it looks like the protocol is broken.
//
// IP_PKTINFO fixes it: the kernel attaches the destination address to each
// received datagram, and the same address can be pinned as the source on the
// reply. That is one socket option and a control message — not a new dependency,
// since golang.org/x/sys was already in the module graph.
//
// # Why the local address is remembered rather than passed
//
// The obvious API takes the local address as a parameter, which has no hidden
// state and is honest about what is happening. It also means threading a new
// argument through every send path in nine servers, which is a large enough
// change that in practice only some of them would adopt it.
//
// So the local address is remembered per peer instead, and the write path looks
// it up: "reply to a peer from wherever it last reached us" is what every one of
// these servers wants, and it makes this a drop-in replacement for *net.UDPConn.
// The cost is a map, bounded the same way the admission gate's is — an unbounded
// one would be the very denial of service that gate exists to prevent.

import (
	"net"
	"net/netip"
	"sync"
	"time"

	xipv4 "golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

const (
	// peerAddrIdle is how long a peer's local-address association is kept after
	// it goes quiet.
	peerAddrIdle = 10 * time.Minute
	// peerAddrMax caps the association table regardless of idleness, so a flood
	// from many sources cannot grow it without bound between sweeps.
	peerAddrMax = 8192
)

// PacketConn is a UDP socket that replies from the address a request arrived on.
// It is a drop-in for the subset of *net.UDPConn these servers use.
type PacketConn struct {
	conn *net.UDPConn
	// pktInfo is false when the socket option is unavailable, in which case
	// this behaves exactly as the bare socket did.
	pktInfo bool
	// v6 is true when the socket is bound to an IPv6 (or dual-stack `::`) address,
	// selecting the IPV6_PKTINFO family for source pinning; false for IPv4.
	v6 bool

	mu     sync.Mutex
	locals map[netip.AddrPort]localEntry
	lastGC time.Time
	now    func() time.Time

	// Batched I/O state. batch is built eagerly in NewPacketConn so the read
	// and write sides never race a lazy init; the message scratch is per side —
	// batchMsgs owned by the single reading goroutine, wbatchMsgs by the single
	// sending goroutine (the pump), mirroring how the socket is already used.
	batch      *xipv4.PacketConn
	batchMsgs  []xipv4.Message
	wbatchMsgs []xipv4.Message
}

type localEntry struct {
	addr netip.Addr
	seen time.Time
}

// NewPacketConn wraps a UDP socket.
//
// Failure to enable the option is not an error. The socket keeps its previous
// behaviour, which is correct on the single-homed hosts that cover most
// deployments; PreservesSource reports which case is in effect.
func NewPacketConn(conn *net.UDPConn) *PacketConn {
	p := &PacketConn{
		conn:   conn,
		locals: map[netip.AddrPort]localEntry{},
		now:    time.Now,
		batch:  xipv4.NewPacketConn(conn),
	}
	p.lastGC = p.now()

	// The socket's address family — not its bound address — selects the PKTINFO
	// variant. Go's "udp" network binds an AF_INET6 (dual-stack) socket even for
	// 0.0.0.0, and such a socket delivers IPV6_PKTINFO for every datagram, v4-
	// mapped ones included; requesting IP_PKTINFO on it is silently inert. Only a
	// socket opened as "udp4" is AF_INET. SO_DOMAIN reports which we have.
	if raw, err := conn.SyscallConn(); err == nil {
		_ = raw.Control(func(fd uintptr) {
			if domain, derr := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_DOMAIN); derr == nil && domain == unix.AF_INET6 {
				p.v6 = true
			}
			level, opt := unix.IPPROTO_IP, unix.IP_PKTINFO
			if p.v6 {
				level, opt = unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO
			}
			if err := unix.SetsockoptInt(int(fd), level, opt, 1); err == nil {
				p.pktInfo = true
			}
		})
	}
	return p
}

// Conn exposes the underlying socket for paths that need it directly.
func (p *PacketConn) Conn() *net.UDPConn { return p.conn }

// PreservesSource reports whether source addresses are actually being pinned, so
// a server can say so at startup rather than assume it.
func (p *PacketConn) PreservesSource() bool { return p.pktInfo }

// ReadFromUDP reads one datagram, recording which local address it was sent to.
func (p *PacketConn) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	if !p.pktInfo {
		return p.conn.ReadFromUDP(b)
	}

	oob := make([]byte, 512)
	n, oobn, _, from, err := p.conn.ReadMsgUDP(b, oob)
	if err != nil {
		return n, from, err
	}
	if local := p.localFromControl(oob[:oobn]); local.IsValid() && from != nil {
		p.remember(from, local)
	}
	return n, from, nil
}

// ReadBatch reads up to len(bufs) datagrams — one recvmmsg syscall for the lot —
// blocking until at least one arrives. Datagram i lands in bufs[i], its length
// in sizes[i], and its source in froms[i]; the count read is returned. sizes and
// froms must be at least len(bufs) long.
//
// Local addresses are recorded exactly as ReadFromUDP records them, so a batched
// read loop keeps the source-address pinning this wrapper exists for: each
// message carries its own IP_PKTINFO control data.
//
// Like the read side of the socket generally, ReadBatch must not be called
// concurrently with itself or ReadFromUDP — the scratch state assumes the one
// reader goroutine every serve loop here already has.
func (p *PacketConn) ReadBatch(bufs [][]byte, sizes []int, froms []*net.UDPAddr) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	if cap(p.batchMsgs) < len(bufs) {
		msgs := make([]xipv4.Message, len(bufs))
		copy(msgs, p.batchMsgs)
		p.batchMsgs = msgs
	}
	msgs := p.batchMsgs[:len(bufs)]
	for i := range msgs {
		msgs[i].Buffers = append(msgs[i].Buffers[:0], bufs[i])
		if p.pktInfo && msgs[i].OOB == nil {
			// One control buffer per slot, sized like ReadFromUDP's and reused
			// for the life of the conn.
			msgs[i].OOB = make([]byte, 512)
		}
		msgs[i].OOB = msgs[i].OOB[:cap(msgs[i].OOB)]
	}
	n, err := p.batch.ReadBatch(msgs, 0)
	for i := range n {
		sizes[i] = msgs[i].N
		from, _ := msgs[i].Addr.(*net.UDPAddr)
		froms[i] = from
		if p.pktInfo && from != nil {
			if local := p.localFromControl(msgs[i].OOB[:msgs[i].NN]); local.IsValid() {
				p.remember(from, local)
			}
		}
	}
	return n, err
}

// WriteBatch sends every packet in pkts to to — one sendmmsg for the lot —
// pinning the reply source exactly as WriteToUDP does when the peer's local
// address is known (one lookup for the batch; each message carries the same
// IP_PKTINFO control data). It returns the number of packets the kernel
// accepted.
//
// Like the pump's send path generally, WriteBatch must not be called
// concurrently with itself — the scratch state assumes the one sending
// goroutine. It is safe alongside the read side and alongside WriteToUDP from
// other goroutines.
func (p *PacketConn) WriteBatch(pkts [][]byte, to *net.UDPAddr) (int, error) {
	if len(pkts) == 0 {
		return 0, nil
	}
	var oob []byte
	if p.pktInfo && to != nil {
		if local, ok := p.lookup(to); ok {
			oob = p.pktInfoOOB(local)
		}
	}
	if cap(p.wbatchMsgs) < len(pkts) {
		msgs := make([]xipv4.Message, len(pkts))
		copy(msgs, p.wbatchMsgs)
		p.wbatchMsgs = msgs
	}
	msgs := p.wbatchMsgs[:len(pkts)]
	for i, pkt := range pkts {
		msgs[i].Buffers = append(msgs[i].Buffers[:0], pkt)
		msgs[i].Addr = to
		msgs[i].OOB = oob
	}
	sent := 0
	for sent < len(pkts) {
		n, err := p.batch.WriteBatch(msgs[sent:], 0)
		sent += n
		if err != nil {
			return sent, err
		}
	}
	return sent, nil
}

// WriteToUDP sends a datagram, from the address this peer last reached us on
// when that is known. A peer we have not heard from falls back to the kernel's
// choice, which is all that is available and is correct for an unsolicited send.
func (p *PacketConn) WriteToUDP(b []byte, to *net.UDPAddr) (int, error) {
	if !p.pktInfo || to == nil {
		return p.conn.WriteToUDP(b, to)
	}

	local, ok := p.lookup(to)
	if !ok {
		return p.conn.WriteToUDP(b, to)
	}
	oob := p.pktInfoOOB(local)
	if oob == nil {
		return p.conn.WriteToUDP(b, to)
	}
	n, _, err := p.conn.WriteMsgUDP(b, oob, to)
	return n, err
}

// pktInfoOOB encodes local as the reply source in a PKTINFO control message of
// the socket's family, or returns nil when local cannot serve as a source for
// this family. For an IPv6 socket As16 covers both native v6 and v4-mapped
// addresses, which the kernel resolves on a dual-stack socket.
func (p *PacketConn) pktInfoOOB(local netip.Addr) []byte {
	if !local.IsValid() {
		return nil
	}
	if p.v6 {
		a := local.As16()
		return unix.PktInfo6(&unix.Inet6Pktinfo{Addr: a})
	}
	if local.Is4() {
		return unix.PktInfo4(&unix.Inet4Pktinfo{Spec_dst: local.As4()})
	}
	return nil
}

// ReadFromUDPAddrPort and WriteToUDPAddrPort are the netip forms, for engines
// that speak netip.AddrPort rather than *net.UDPAddr. They are not a second
// implementation — they convert and delegate — so a protocol does not have to
// choose between the address type it wants and having its source address
// preserved. Nebula wanted exactly that, and for a while had a private adapter
// over a bare socket instead, which quietly opted it out of this whole file.
func (p *PacketConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	n, from, err := p.ReadFromUDP(b)
	if from == nil {
		return n, netip.AddrPort{}, err
	}
	ap, ok := addrPortOf(from)
	if !ok {
		return n, netip.AddrPort{}, err
	}
	return n, ap, err
}

func (p *PacketConn) WriteToUDPAddrPort(b []byte, to netip.AddrPort) (int, error) {
	return p.WriteToUDP(b, net.UDPAddrFromAddrPort(to))
}

// Close closes the socket.
func (p *PacketConn) Close() error { return p.conn.Close() }

// LocalAddr is the socket's bound address.
func (p *PacketConn) LocalAddr() net.Addr { return p.conn.LocalAddr() }

// SetReadDeadline forwards to the socket.
func (p *PacketConn) SetReadDeadline(t time.Time) error { return p.conn.SetReadDeadline(t) }

func (p *PacketConn) remember(from *net.UDPAddr, local netip.Addr) {
	ap, ok := addrPortOf(from)
	if !ok {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	p.gc(now)
	p.locals[ap] = localEntry{addr: local, seen: now}
}

func (p *PacketConn) lookup(to *net.UDPAddr) (netip.Addr, bool) {
	ap, ok := addrPortOf(to)
	if !ok {
		return netip.Addr{}, false
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.locals[ap]
	return e.addr, ok
}

// gc bounds the association table. Caller holds p.mu.
func (p *PacketConn) gc(now time.Time) {
	// Size is checked every call, because a flood can outrun the timer between
	// sweeps and the point of this table is not to become the leak that the
	// admission gate exists to prevent.
	overSize := len(p.locals) > peerAddrMax
	if !overSize && now.Sub(p.lastGC) < peerAddrIdle {
		return
	}
	p.lastGC = now

	for ap, e := range p.locals {
		if now.Sub(e.seen) > peerAddrIdle {
			delete(p.locals, ap)
		}
	}
	// If idle eviction was not enough, entries are arriving faster than they
	// age out. Dropping the table is safe: every entry is a cache that the next
	// datagram from that peer re-establishes, and the behaviour while it is
	// empty is exactly what this wrapper replaces.
	if len(p.locals) > peerAddrMax {
		p.locals = map[netip.AddrPort]localEntry{}
	}
}

func addrPortOf(a *net.UDPAddr) (netip.AddrPort, bool) {
	ip, ok := netip.AddrFromSlice(a.IP)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(a.Port)), true
}

// localFromControl extracts the destination address from a datagram's control
// messages, returning the zero Addr when absent. It reads the PKTINFO variant of
// the socket's family — decoding by offset rather than through unsafe, since the
// layout is fixed by the kernel ABI and x/sys ships an encoder but no parser.
func (p *PacketConn) localFromControl(oob []byte) netip.Addr {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.Addr{}
	}
	for _, m := range msgs {
		if p.v6 {
			if m.Header.Level != unix.IPPROTO_IPV6 || m.Header.Type != unix.IPV6_PKTINFO {
				continue
			}
			// struct in6_pktinfo is { in6_addr ipi6_addr; u32 ipi6_ifindex }: the
			// 16-octet destination address is at offset 0.
			if len(m.Data) < 16 {
				continue
			}
			return netip.AddrFrom16([16]byte(m.Data[0:16]))
		}
		if m.Header.Level != unix.IPPROTO_IP || m.Header.Type != unix.IP_PKTINFO {
			continue
		}
		// struct in_pktinfo is { int32 ifindex; be32 spec_dst; be32 addr }.
		if len(m.Data) < 12 {
			continue
		}
		// spec_dst is the address the datagram was addressed to, which is what a
		// reply must come from. addr is the interface's primary address, which
		// differs on a host with several addresses on one interface.
		return netip.AddrFrom4([4]byte(m.Data[4:8]))
	}
	return netip.Addr{}
}
