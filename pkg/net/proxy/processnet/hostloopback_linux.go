//go:build linux && !android

package processnet

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/relay"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/yuhaiin/sessionnet"
)

// Limits of one session's host loopback forwarding.
const (
	hostLoopbackMaxTCP     = 1024
	hostLoopbackMaxUDP     = 256
	hostLoopbackDialTime   = 10 * time.Second
	hostLoopbackLogBackoff = 10 * time.Second
)

// UDP flows without traffic in either direction for hostLoopbackUDPIdle are
// closed; variables so tests can shorten them.
var (
	hostLoopbackUDPIdle = 60 * time.Second
	hostLoopbackUDPReap = 5 * time.Second
)

// HostLoopback serves the loopback sockets a session reserved for its
// mappings (sessionnet.LoopbackForward) and relays every connection and UDP
// flow to the mapped host loopback endpoint. The sockets live in the session
// network namespace; the host side is opened by the dialer in Yuhaiin's own
// namespace, so nothing is routed and nothing can re-enter a session.
type HostLoopback struct {
	ctx       context.Context
	cancel    context.CancelFunc
	dialer    HostLoopbackDialer
	scope     netapi.ProcessDumper
	inboundID string
	tcpSlots  chan struct{}
	udpFlows  atomic.Int64
	wg        sync.WaitGroup
	closers   []func() error
	once      sync.Once
	err       error
	logged    sync.Map // mapping string -> last warning (time.Time)
}

// StartHostLoopback starts forwarding for a session opened with
// HostLoopbackForwards(mappings). scope resolves the session processes for
// connection accounting and may be nil. If anything fails, everything already
// started is closed again.
func StartHostLoopback(owner *sessionnet.Session, mappings []HostLoopbackMapping, dialer HostLoopbackDialer, scope netapi.ProcessDumper, inboundID string) (_ *HostLoopback, err error) {
	if err := ValidateHostLoopbackMappings(mappings); err != nil {
		return nil, err
	}
	if dialer == nil {
		dialer = DirectHostLoopbackDialer{Timeout: hostLoopbackDialTime}
	}
	sockets, err := owner.LoopbackSockets()
	if err != nil {
		return nil, fmt.Errorf("host loopback forwarding: %w", err)
	}
	bySession := make(map[sessionnet.LoopbackForward]*sessionnet.LoopbackSocket, len(sockets))
	for i := range sockets {
		bySession[sockets[i].Forward] = &sockets[i]
	}
	defer func() {
		for _, sock := range bySession {
			_ = sock.File.Close()
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	h := &HostLoopback{ctx: ctx, cancel: cancel, dialer: dialer, scope: scope, inboundID: inboundID,
		tcpSlots: make(chan struct{}, hostLoopbackMaxTCP)}
	defer func() {
		if err != nil {
			_ = h.Close()
		}
	}()
	for _, m := range mappings {
		key := sessionnet.LoopbackForward{Network: m.Network, Address: m.Session}
		sock := bySession[key]
		if sock == nil {
			return nil, fmt.Errorf("host loopback forwarding: the session has no socket for %s", m)
		}
		delete(bySession, key)
		switch m.Network {
		case "tcp":
			l, err := net.FileListener(sock.File)
			_ = sock.File.Close()
			if err != nil {
				return nil, fmt.Errorf("host loopback forwarding %s: %w", m, err)
			}
			h.closers = append(h.closers, l.Close)
			h.wg.Go(func() { h.acceptLoop(m, l) })
		case "udp":
			pc, err := net.FilePacketConn(sock.File)
			_ = sock.File.Close()
			if err != nil {
				return nil, fmt.Errorf("host loopback forwarding %s: %w", m, err)
			}
			h.closers = append(h.closers, pc.Close)
			u := &udpForward{h: h, mapping: m, session: pc, flows: map[netip.AddrPort]*udpFlow{}}
			h.wg.Go(u.readLoop)
			h.wg.Go(u.reapLoop)
		}
		slog.Info("ssh inbound: host loopback mapping applied", "inbound", inboundID, "mapping", m.String())
	}
	return h, nil
}

// Close stops accepting, closes every forwarded connection and UDP flow and
// waits for all goroutines. It is idempotent.
func (h *HostLoopback) Close() error {
	h.once.Do(func() {
		h.cancel()
		for _, c := range h.closers {
			if err := c(); err != nil && !errors.Is(err, net.ErrClosed) {
				h.err = errors.Join(h.err, err)
			}
		}
		h.wg.Wait()
		slog.Debug("ssh inbound: host loopback forwarding closed", "inbound", h.inboundID)
	})
	return h.err
}

// warn logs a forwarding failure at most once per mapping per backoff, so a
// client retrying a stopped host service cannot flood the log.
func (h *HostLoopback) warn(m HostLoopbackMapping, msg string, err error) {
	now := time.Now()
	if last, ok := h.logged.Load(m.String()); ok && now.Sub(last.(time.Time)) < hostLoopbackLogBackoff {
		slog.Debug(msg, "inbound", h.inboundID, "mapping", m.String(), "err", err)
		return
	}
	h.logged.Store(m.String(), now)
	slog.Warn(msg, "inbound", h.inboundID, "mapping", m.String(), "err", err)
}

// flow describes a session socket and resolves its process when possible.
func (h *HostLoopback) flow(m HostLoopbackMapping, source netip.AddrPort) HostLoopbackFlow {
	flow := HostLoopbackFlow{Mapping: m, Source: source, InboundID: h.inboundID}
	if h.scope != nil {
		// The session process's socket is source -> session endpoint.
		p, err := h.scope.ProcessName(m.Network, netapi.ParseNetipAddrPort(m.Network, source), netapi.ParseNetipAddrPort(m.Network, m.Session))
		if err == nil {
			flow.Process, flow.PID, flow.UID = p.Path, p.Pid, p.Uid
		}
	}
	return flow
}

func (h *HostLoopback) acceptLoop(m HostLoopbackMapping, l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			if h.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				h.warn(m, "ssh inbound: host loopback accept failed", err)
			}
			return
		}
		select {
		case h.tcpSlots <- struct{}{}:
		default:
			h.warn(m, "ssh inbound: host loopback connection limit reached", fmt.Errorf("%d connections", hostLoopbackMaxTCP))
			_ = c.Close()
			continue
		}
		h.wg.Go(func() {
			defer func() { <-h.tcpSlots }()
			h.serveTCP(m, c)
		})
	}
}

func (h *HostLoopback) serveTCP(m HostLoopbackMapping, c net.Conn) {
	defer c.Close()
	source, _ := netip.ParseAddrPort(c.RemoteAddr().String())
	flow := h.flow(m, source)
	ctx, cancel := context.WithTimeout(h.ctx, hostLoopbackDialTime)
	remote, err := h.dialer.DialTCP(ctx, flow)
	cancel()
	if err != nil {
		h.warn(m, "ssh inbound: host loopback connection failed", err)
		return
	}
	defer remote.Close()
	slog.Debug("ssh inbound: host loopback connection opened", "inbound", h.inboundID, "mapping", m.String(), "source", source, "process", flow.Process)
	relay.RelayContext(h.ctx, c, remote, "ssh host loopback", m.String(), "src", source)
	slog.Debug("ssh inbound: host loopback connection closed", "inbound", h.inboundID, "mapping", m.String(), "source", source)
}

type udpForward struct {
	h       *HostLoopback
	mapping HostLoopbackMapping
	session net.PacketConn
	mu      sync.Mutex
	flows   map[netip.AddrPort]*udpFlow
}

type udpFlow struct {
	host     net.PacketConn
	source   netip.AddrPort
	lastSeen atomic.Int64
}

func (u *udpForward) readLoop() {
	defer u.closeAll()
	buf := pool.GetBytes(65535)
	defer pool.PutBytes(buf)
	hostAddr := net.UDPAddrFromAddrPort(u.mapping.Host)
	for {
		n, from, err := u.session.ReadFrom(buf)
		if err != nil {
			if u.h.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				u.h.warn(u.mapping, "ssh inbound: host loopback UDP read failed", err)
			}
			return
		}
		source, ok := netip.AddrFromSlice(from.(*net.UDPAddr).IP)
		if !ok {
			continue
		}
		src := netip.AddrPortFrom(source.Unmap(), uint16(from.(*net.UDPAddr).Port))
		flow, err := u.lookup(src)
		if err != nil {
			u.h.warn(u.mapping, "ssh inbound: host loopback UDP flow failed", err)
			continue
		}
		flow.lastSeen.Store(time.Now().UnixNano())
		if _, err := flow.host.WriteTo(buf[:n], hostAddr); err != nil {
			u.h.warn(u.mapping, "ssh inbound: host loopback UDP send failed", err)
		}
	}
}

// lookup returns the flow of a session source, opening a host socket for a
// new one. Datagrams keep their boundaries: each is one write.
func (u *udpForward) lookup(src netip.AddrPort) (*udpFlow, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if flow := u.flows[src]; flow != nil {
		return flow, nil
	}
	if u.h.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if u.h.udpFlows.Load() >= hostLoopbackMaxUDP {
		return nil, fmt.Errorf("UDP flow limit of %d reached", hostLoopbackMaxUDP)
	}
	ctx, cancel := context.WithTimeout(u.h.ctx, hostLoopbackDialTime)
	host, err := u.h.dialer.ListenUDP(ctx, u.h.flow(u.mapping, src))
	cancel()
	if err != nil {
		return nil, err
	}
	flow := &udpFlow{host: host, source: src}
	flow.lastSeen.Store(time.Now().UnixNano())
	u.flows[src] = flow
	u.h.udpFlows.Add(1)
	u.h.wg.Go(func() { u.replyLoop(flow) })
	slog.Debug("ssh inbound: host loopback UDP flow opened", "inbound", u.h.inboundID, "mapping", u.mapping.String(), "source", src)
	return flow, nil
}

// replyLoop returns host replies to the session source. Only datagrams from
// the mapped host endpoint are accepted.
func (u *udpForward) replyLoop(flow *udpFlow) {
	defer u.remove(flow)
	buf := pool.GetBytes(65535)
	defer pool.PutBytes(buf)
	to := net.UDPAddrFromAddrPort(flow.source)
	for {
		n, from, err := flow.host.ReadFrom(buf)
		if err != nil {
			return
		}
		addr, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		if ap := addr.AddrPort(); netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()) != u.mapping.Host {
			continue // not the mapped host service
		}
		flow.lastSeen.Store(time.Now().UnixNano())
		if _, err := u.session.WriteTo(buf[:n], to); err != nil {
			if u.h.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			u.h.warn(u.mapping, "ssh inbound: host loopback UDP reply failed", err)
		}
	}
}

func (u *udpForward) remove(flow *udpFlow) {
	u.mu.Lock()
	if u.flows[flow.source] == flow {
		delete(u.flows, flow.source)
		u.h.udpFlows.Add(-1)
	}
	u.mu.Unlock()
	_ = flow.host.Close()
}

// reapLoop closes flows idle for hostLoopbackUDPIdle.
func (u *udpForward) reapLoop() {
	ticker := time.NewTicker(hostLoopbackUDPReap)
	defer ticker.Stop()
	for {
		select {
		case <-u.h.ctx.Done():
			return
		case <-ticker.C:
			deadline := time.Now().Add(-hostLoopbackUDPIdle).UnixNano()
			u.mu.Lock()
			for _, flow := range u.flows {
				if flow.lastSeen.Load() < deadline {
					slog.Debug("ssh inbound: host loopback UDP flow expired", "inbound", u.h.inboundID, "mapping", u.mapping.String(), "source", flow.source)
					// The reply loop removes the flow once its socket closes.
					_ = flow.host.Close()
				}
			}
			u.mu.Unlock()
		}
	}
}

func (u *udpForward) closeAll() {
	u.mu.Lock()
	flows := make([]*udpFlow, 0, len(u.flows))
	for _, flow := range u.flows {
		flows = append(flows, flow)
	}
	u.mu.Unlock()
	for _, flow := range flows {
		_ = flow.host.Close()
	}
}
