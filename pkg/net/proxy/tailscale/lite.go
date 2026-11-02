package tailscale

import (
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	lite "github.com/yuhaiin/tailscale-lite"
)

func init() {
	register.RegisterContractPoint("tailscale-lite", func(config contractnode.TailscaleLite, p netapi.Proxy) (netapi.Proxy, error) {
		return NewLite(Config{AuthKey: config.AuthKey, Hostname: config.Hostname, ControlURL: config.ControlURL, Debug: config.Debug}, p)
	})
}

// Lite owns an independent client and identity. owner reuses the existing
// instance lifetime, underlay ancestry and recursion graph; its tsnet server
// is never initialized. Both outbound types can coexist, including in a chain.
type Lite struct {
	netapi.EmptyDispatch
	owner  *Tailscale
	client *lite.Client
	tun    *tailnetTun
}

func NewLite(c Config, upstream netapi.Proxy) (netapi.Proxy, error) {
	p, err := New(c, upstream)
	if err != nil {
		return nil, err
	}
	return &Lite{owner: p.(*Tailscale)}, nil
}

func liteStatePath(base string, c Config) (string, error) {
	salt := fmt.Appendf(nil, "yuhaiin/tailscale-lite/state/v1:%d:%s%d:%s", len(c.Hostname), c.Hostname, len(c.ControlURL), c.ControlURL)
	identity, err := pbkdf2.Key(sha256.New, c.AuthKey, salt, 600_000, 32)
	if err != nil {
		return "", fmt.Errorf("derive tailscale-lite state identity: %w", err)
	}
	return filepath.Join(base, "tailscale-lite", "v1-"+hex.EncodeToString(identity)), nil
}

func (t *Lite) init(ctx context.Context) (*lite.Client, error) {
	if err := checkLoop(ctx, t.owner); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if netapi.IsBackgroundProbe(ctx) {
		if !t.owner.mu.TryLock() {
			return nil, netapi.ErrBackgroundProbeUnavailable
		}
	} else {
		t.owner.mu.Lock()
	}
	defer t.owner.mu.Unlock()
	if t.owner.closed {
		return nil, net.ErrClosed
	}
	if t.client != nil {
		return t.client, nil
	}
	if netapi.IsBackgroundProbe(ctx) {
		return nil, netapi.ErrBackgroundProbeUnavailable
	}
	dir, err := liteStatePath(configuration.DataDir.Load(), t.owner.config)
	if err != nil {
		return nil, err
	}
	stateOwners.Lock()
	if stateOwners.paths[dir] != nil {
		stateOwners.Unlock()
		return nil, errors.New("tailscale identity state already in use")
	}
	stateOwners.paths[dir] = t.owner
	stateOwners.Unlock()
	release := func() { stateOwners.Lock(); delete(stateOwners.paths, dir); stateOwners.Unlock() }
	path := filepath.Join(dir, "lite.json")
	n := newTailnetTun()
	u := &underlay{owner: t.owner, ancestors: appendLoop(ctx, t.owner)}
	logger := log.InfoFormat
	if !t.owner.config.Debug {
		logger = func(string, ...any) {}
	}
	client, err := lite.New(lite.Config{
		Hostname: t.owner.config.Hostname, ControlURL: t.owner.config.ControlURL,
		AuthKey: t.owner.config.AuthKey, StatePath: path, Device: n,
		Underlay: u.network(), RequireUnderlay: true, Logf: logger,
		TailnetDialTCP: func(ctx context.Context, target netip.AddrPort) (net.Conn, error) {
			stack, err := n.await()
			if err != nil {
				return nil, err
			}
			return stack.DialContextTCP(ctx, net.TCPAddrFromAddrPort(target))
		},
		TailnetDialUDP: func(ctx context.Context, target netip.AddrPort) (net.Conn, error) {
			stack, err := n.await()
			if err != nil {
				return nil, err
			}
			var local netip.Addr
			if target.Addr().Is4() {
				n.mu.Lock()
				local = n.v4
				n.mu.Unlock()
			} else {
				n.mu.Lock()
				local = n.v6
				n.mu.Unlock()
			}
			if !local.IsValid() {
				return nil, errors.New("tailscale: no local address for Tailnet DNS family")
			}
			return stack.DialUDP(net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, 0)), net.UDPAddrFromAddrPort(target))
		},
		OnAddresses: func(prefixes []netip.Prefix) error {
			var v4, v6 netip.Addr
			for _, prefix := range prefixes {
				if !prefix.IsSingleIP() {
					return fmt.Errorf("tailscale: invalid assigned address %v", prefix)
				}
				if prefix.Addr().Is4() {
					v4 = prefix.Addr()
				} else if prefix.Addr().Is6() {
					v6 = prefix.Addr()
				}
			}
			return n.configure(v4, v6)
		},
	})
	if err != nil {
		_ = n.Close()
		release()
		return nil, err
	}
	t.client, t.tun, t.owner.stateDir = client, n, dir
	return client, nil
}

func (t *Lite) ready(ctx context.Context) (*lite.Client, error) {
	client, err := t.init(ctx)
	if err != nil {
		return nil, err
	}
	if err := client.WaitReady(ctx); err != nil {
		return nil, err
	}
	// Local DNS needs only the authorized map. Do not wait for control to
	// echo SelfNode endpoints or HomeDERP: some control streams omit them.
	if t.owner.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	t.owner.mu.Lock()
	n := t.tun
	t.owner.mu.Unlock()
	if n == nil {
		return nil, net.ErrClosed
	}
	n.metrics.Do(func() { go serveMetrics(n) })
	return client, nil
}

func (t *Lite) Close() error {
	t.owner.mu.Lock()
	defer t.owner.mu.Unlock()
	if t.owner.closed {
		return nil
	}
	t.owner.closed = true
	t.owner.cancel()
	defer forgetUnderlay(t.owner)
	var err error
	if t.client != nil {
		err = t.client.Close()
	}
	if t.owner.stateDir != "" {
		stateOwners.Lock()
		delete(stateOwners.paths, t.owner.stateDir)
		stateOwners.Unlock()
	}
	return err
}

// resolveLiteAddr resolves only control-authorized Tailnet routes. A miss must
// never fall through to an ordinary OS socket, including names not in MagicDNS.
func resolveLiteAddr(ctx context.Context, client *lite.Client, network string, addr netapi.Address) (netip.AddrPort, error) {
	if err := ctx.Err(); err != nil {
		return netip.AddrPort{}, err
	}
	if client == nil || addr == nil {
		return netip.AddrPort{}, errors.New("tailscale: client unavailable")
	}
	var ips []netip.Addr
	if addr.IsFqdn() {
		var owned bool
		ips, owned = client.LookupIP(addr.Hostname())
		if owned && len(ips) == 0 {
			// A name within an authoritative MagicDNS zone must never
			// escape to a default resolver if it is absent.
			return netip.AddrPort{}, fmt.Errorf("tailscale: no MagicDNS record for %s", addr.Hostname())
		}
		if !owned {
			// The legacy tsnet UserDialPlan used the control-supplied DNS
			// configuration for Split DNS and ExtraRecords as well as the
			// MagicDNS table. Preserve that behavior without host fallback.
			var err error
			ips, err = resolveLiteDNSName(ctx, client, addr.Hostname())
			if err != nil {
				return netip.AddrPort{}, fmt.Errorf("tailscale DNS: %w", err)
			}
		}
	} else {
		ips = []netip.Addr{addr.(netapi.IPAddress).AddrPort().Addr()}
	}
	self := client.Snapshot().Addresses
	for _, ip := range ips {
		ip = ip.Unmap()
		if network == "udp4" && !ip.Is4() || network == "udp6" && !ip.Is6() {
			continue
		}
		allowed := false
		for _, local := range self {
			if local.Addr() == ip {
				allowed = true
				break
			}
		}
		if !allowed {
			_, allowed = client.Route(ip)
		}
		if allowed {
			return netip.AddrPortFrom(ip, addr.Port()), nil
		}
	}
	return netip.AddrPort{}, fmt.Errorf("tailscale: no authorized tailnet route for %s", addr)
}

func (t *Lite) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	client, err := t.ready(ctx)
	if err != nil {
		return nil, err
	}
	if isServiceDNS(addr) {
		one, two := net.Pipe()
		stop := context.AfterFunc(t.owner.ctx, func() { _ = one.Close() })
		go func() { defer stop(); defer one.Close(); serveLiteDNS(one, client) }()
		return two, nil
	}
	ip, err := resolveLiteAddr(ctx, client, "tcp", addr)
	if err != nil {
		return nil, err
	}
	t.owner.mu.Lock()
	n := t.tun
	t.owner.mu.Unlock()
	network, err := n.await()
	if err != nil {
		return nil, err
	}
	return network.DialContextTCP(ctx, net.TCPAddrFromAddrPort(ip))
}

func (t *Lite) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	client, err := t.ready(ctx)
	if err != nil {
		return nil, err
	}
	if isServiceDNS(addr) {
		return newDNSPacket(t.owner.ctx, func(ctx context.Context, packet []byte, _ string, _ netip.AddrPort) ([]byte, error) {
			return liteDNSQuery(ctx, client, packet)
		}, addr.(netapi.IPAddress).AddrPort()), nil
	}
	ip, err := resolveLiteAddr(ctx, client, "udp", addr)
	if err != nil {
		return nil, err
	}
	var v4, v6 netip.Addr
	for _, prefix := range client.Snapshot().Addresses {
		if prefix.Addr().Is4() {
			v4 = prefix.Addr()
		} else if prefix.Addr().Is6() {
			v6 = prefix.Addr()
		}
	}
	local, networkName := v4, "udp4"
	if ip.Addr().Is6() {
		local, networkName = v6, "udp6"
	}
	if !local.IsValid() {
		return nil, errors.New("tailscale: no local address for destination family")
	}
	t.owner.mu.Lock()
	n := t.tun
	t.owner.mu.Unlock()
	stack, err := n.await()
	if err != nil {
		return nil, err
	}
	pc, err := stack.DialUDP(&net.UDPAddr{IP: net.IP(local.AsSlice())}, nil)
	if err != nil {
		return nil, err
	}
	pcCtx, cancel := context.WithCancel(t.owner.ctx)
	return &litePacketConn{PacketConn: pc, server: client, ctx: pcCtx,
		cancel: cancel, network: networkName, writeDeadline: pipe.MakePipeDeadline()}, nil
}

func (t *Lite) PacketConnPacket(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	return t.PacketConn(ctx, addr)
}

func (t *Lite) Ping(ctx context.Context, addr netapi.Address) (uint64, error) {
	client, err := t.ready(ctx)
	if err != nil {
		return 0, err
	}
	ip, err := resolveLiteAddr(ctx, client, "tcp", addr)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, configuration.Timeout)
	defer cancel()
	stop := context.AfterFunc(t.owner.ctx, cancel)
	defer stop()
	latency, err := client.Ping(ctx, ip.Addr())
	return uint64(latency), err
}

// litePacketConn is a real unconnected socket. Every destination is checked
// and resolved through this server; ordinary names cannot escape to host sockets.
type litePacketConn struct {
	net.PacketConn
	server        *lite.Client
	ctx           context.Context
	network       string
	cancel        context.CancelFunc
	writeDeadline pipe.PipeDeadline
}

func (p *litePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	a, err := netapi.ParseSysAddr(addr)
	if err != nil {
		return 0, err
	}
	if p.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	ctx := p.ctx
	// IP datagrams avoid a timer and watcher goroutine. Only hostname resolution
	// can block before the socket sees its write deadline.
	if a.IsFqdn() {
		lookupCtx, cancel := context.WithTimeout(ctx, configuration.ResolverTimeout)
		defer cancel()
		var stop context.CancelFunc
		ctx, stop, err = withWriteDeadline(lookupCtx, &p.writeDeadline)
		if err != nil {
			return 0, err
		}
		defer stop()
	}
	ip, err := resolveLiteAddr(ctx, p.server, p.network, a)
	if cause := context.Cause(ctx); cause != nil {
		if p.ctx.Err() != nil {
			return 0, net.ErrClosed
		}
		return 0, cause
	}
	if err != nil {
		return 0, err
	}
	if p.network == "udp4" && !ip.Addr().Is4() || p.network == "udp6" && !ip.Addr().Is6() {
		return 0, errors.New("tailscale UDP destination does not match socket address family")
	}
	return p.PacketConn.WriteTo(b, net.UDPAddrFromAddrPort(ip))
}

func (p *litePacketConn) Close() error {
	p.cancel()
	p.writeDeadline.Set(time.Time{})
	return p.PacketConn.Close()
}
func (p *litePacketConn) SetWriteDeadline(t time.Time) error {
	if p.ctx.Err() != nil {
		return net.ErrClosed
	}
	p.writeDeadline.Set(t)
	return p.PacketConn.SetWriteDeadline(t)
}
func (p *litePacketConn) SetDeadline(t time.Time) error {
	if err := p.SetReadDeadline(t); err != nil {
		return err
	}
	return p.SetWriteDeadline(t)
}
