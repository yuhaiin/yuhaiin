package tailscale

import (
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	lite "github.com/yuhaiin/tailscale-lite"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/tsaddr"
)

var Mux atomic.Pointer[http.ServeMux]

// A state directory belongs to one running server. In particular a replacement
// configuration must not open the old server's state before it has shut down.
var stateOwners = struct {
	sync.Mutex
	paths map[string]*Tailscale
}{paths: make(map[string]*Tailscale)}

func init() {
	register.RegisterContractPoint("tailscale", func(config contractnode.Tailscale, p netapi.Proxy) (netapi.Proxy, error) {
		return New(Config{AuthKey: config.AuthKey, Hostname: config.Hostname, ControlURL: config.ControlURL, Debug: config.Debug}, p)
	})
}

type Tailscale struct {
	netapi.EmptyDispatch
	dialer   netapi.Proxy
	config   Config
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	client   *lite.Client
	tun      *tailnetTun
	closed   bool
	stateDir string
}

type Config struct {
	AuthKey    string `json:"auth_key"`
	Hostname   string `json:"hostname"`
	ControlURL string `json:"control_url"`
	Debug      bool   `json:"debug"`
}

func New(c Config, upstream netapi.Proxy) (netapi.Proxy, error) {
	if c.AuthKey == "" {
		return nil, errors.New("auth_key is required")
	}
	if upstream == nil || register.IsZero(upstream) {
		upstream = direct.Default
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Tailscale{dialer: upstream, config: c, ctx: ctx, cancel: cancel}, nil
}

// statePath derives a deterministic opaque identity without exposing a fast
// credential digest in directory names. Public configuration forms a stable,
// length-delimited salt; this is an identity namespace, not a password verifier.
func statePath(base string, c Config) (string, error) {
	salt := fmt.Appendf(nil, "yuhaiin/tailscale/state/v2:%d:%s%d:%s", len(c.Hostname), c.Hostname, len(c.ControlURL), c.ControlURL)
	identity, err := pbkdf2.Key(sha256.New, c.AuthKey, salt, 600_000, 32)
	if err != nil {
		return "", fmt.Errorf("derive tailscale state identity: %w", err)
	}
	return filepath.Join(base, "tailscale", "v2-"+hex.EncodeToString(identity)), nil
}

func (t *Tailscale) init(ctx context.Context) (*lite.Client, error) {
	if err := checkLoop(ctx, t); err != nil { return nil, err }
	if err := ctx.Err(); err != nil { return nil, err }
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed { return nil, net.ErrClosed }
	if t.client != nil { return t.client, nil }
	dir, err := statePath(configuration.DataDir.Load(), t.config)
	if err != nil { return nil, err }
	stateOwners.Lock()
	if stateOwners.paths[dir] != nil {
		stateOwners.Unlock()
		return nil, errors.New("tailscale identity state already in use")
	}
	stateOwners.paths[dir] = t
	stateOwners.Unlock()
	release := func() { stateOwners.Lock(); delete(stateOwners.paths, dir); stateOwners.Unlock() }
	if err := migrateState(configuration.DataDir.Load(), dir, t.config.Hostname); err != nil {
		release()
		return nil, err
	}
	path := filepath.Join(dir, "lite.json")
	// tsnet's profile-format identity cannot be fed to the lite JSON store.
	// Fail closed instead of silently creating a second identity.
	if _, err := os.Stat(filepath.Join(dir, "tailscaled.state")); err == nil {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			release()
			return nil, errors.New("tailscale-lite: existing tsnet state requires explicit identity migration; preserving old tailscaled.state")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		release()
		return nil, err
	}
	n := newTailnetTun()
	u := &underlay{owner: t, ancestors: appendLoop(ctx, t)}
	logger := log.InfoFormat
	if !t.config.Debug { logger = func(string, ...any) {} }
	client, err := lite.New(lite.Config{
		Hostname: t.config.Hostname, ControlURL: t.config.ControlURL,
		AuthKey: t.config.AuthKey, StatePath: path, Device: n,
		Underlay: u.network(), RequireUnderlay: true, Logf: logger,
		OnAddresses: func(prefixes []netip.Prefix) error {
			var v4, v6 netip.Addr
			for _, prefix := range prefixes {
				if !prefix.IsSingleIP() { return fmt.Errorf("tailscale: invalid assigned address %v", prefix) }
				if prefix.Addr().Is4() { v4 = prefix.Addr() } else if prefix.Addr().Is6() { v6 = prefix.Addr() }
			}
			return n.configure(v4, v6)
		},
	})
	if err != nil { _ = n.Close(); release(); return nil, err }
	t.client, t.tun, t.stateDir = client, n, dir
	return client, nil
}

func serveMetrics(n *tailnetTun) {
	network, err := n.await()
	if err != nil {
		return
	}
	lis, err := network.ListenTCP(&net.TCPAddr{Port: 80})
	if err != nil {
		log.Debug("tailscale listen metrics failed", "err", err)
		return
	}
	go func() {
		defer lis.Close()
		err := http.Serve(lis, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if mux := Mux.Load(); mux != nil {
				mux.ServeHTTP(w, r)
			}
		}))
		if err != nil && !errors.Is(err, net.ErrClosed) {
			log.Debug("tailscale serve metrics stopped", "err", err)
		}
	}()
}

func (t *Tailscale) ready(ctx context.Context) (*lite.Client, error) {
	client, err := t.init(ctx)
	if err != nil { return nil, err }
	if err := client.WaitReady(ctx); err != nil { return nil, err }
	if t.ctx.Err() != nil { return nil, net.ErrClosed }
	t.mu.Lock()
	n := t.tun
	t.mu.Unlock()
	if n == nil { return nil, net.ErrClosed }
	n.metrics.Do(func() { go serveMetrics(n) })
	return client, nil
}

func (t *Tailscale) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	t.cancel()
	defer forgetUnderlay(t)
	var err error
	if t.client != nil {
		err = t.client.Close()
	}
	if t.stateDir != "" {
		stateOwners.Lock()
		delete(stateOwners.paths, t.stateDir)
		stateOwners.Unlock()
	}
	return err
}

// resolveAddr resolves only control-authorized Tailnet routes. A miss must
// never fall through to an ordinary OS socket, including names not in MagicDNS.
func resolveAddr(ctx context.Context, client *lite.Client, network string, addr netapi.Address) (netip.AddrPort, error) {
	if err := ctx.Err(); err != nil { return netip.AddrPort{}, err }
	if client == nil || addr == nil { return netip.AddrPort{}, errors.New("tailscale: client unavailable") }
	var ips []netip.Addr
	if addr.IsFqdn() {
		var owned bool
		ips, owned = client.LookupIP(addr.Hostname())
		if !owned || len(ips) == 0 {
			return netip.AddrPort{}, fmt.Errorf("tailscale: no authorized MagicDNS record for %s", addr.Hostname())
		}
	} else {
		ips = []netip.Addr{addr.(netapi.IPAddress).AddrPort().Addr()}
	}
	var self []netip.Prefix
	self = client.Snapshot().Addresses
	for _, ip := range ips {
		ip = ip.Unmap()
		if network == "udp4" && !ip.Is4() || network == "udp6" && !ip.Is6() { continue }
		allowed := false
		for _, local := range self { if local.Addr() == ip { allowed = true; break } }
		if !allowed { _, allowed = client.Route(ip) }
		if allowed { return netip.AddrPortFrom(ip, addr.Port()), nil }
	}
	return netip.AddrPort{}, fmt.Errorf("tailscale: no authorized tailnet route for %s", addr)
}

func isServiceDNS(addr netapi.Address) bool {
	if addr.IsFqdn() || addr.Port() != 53 {
		return false
	}
	ip := addr.(netapi.IPAddress).AddrPort().Addr().Unmap()
	return ip == tsaddr.TailscaleServiceIP() || ip == tsaddr.TailscaleServiceIPv6()
}

func (t *Tailscale) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	client, err := t.ready(ctx)
	if err != nil { return nil, err }
	if isServiceDNS(addr) {
		one, two := net.Pipe()
		stop := context.AfterFunc(t.ctx, func() { _ = one.Close() })
		go func() { defer stop(); defer one.Close(); serveLiteDNS(one, client) }()
		return two, nil
	}
	ip, err := resolveAddr(ctx, client, "tcp", addr)
	if err != nil { return nil, err }
	t.mu.Lock(); n := t.tun; t.mu.Unlock()
	network, err := n.await()
	if err != nil { return nil, err }
	return network.DialContextTCP(ctx, net.TCPAddrFromAddrPort(ip))
}

func (t *Tailscale) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	client, err := t.ready(ctx)
	if err != nil { return nil, err }
	if isServiceDNS(addr) {
		return newDNSPacket(t.ctx, func(ctx context.Context, packet []byte, _ string, _ netip.AddrPort) ([]byte, error) {
			return liteDNSQuery(ctx, client, packet)
		}, addr.(netapi.IPAddress).AddrPort()), nil
	}
	ip, err := resolveAddr(ctx, client, "udp", addr)
	if err != nil { return nil, err }
	var v4, v6 netip.Addr
	for _, prefix := range client.Snapshot().Addresses {
		if prefix.Addr().Is4() { v4 = prefix.Addr() } else if prefix.Addr().Is6() { v6 = prefix.Addr() }
	}
	local, networkName := v4, "udp4"
	if ip.Addr().Is6() { local, networkName = v6, "udp6" }
	if !local.IsValid() { return nil, errors.New("tailscale: no local address for destination family") }
	t.mu.Lock(); n := t.tun; t.mu.Unlock()
	stack, err := n.await()
	if err != nil { return nil, err }
	pc, err := stack.DialUDP(&net.UDPAddr{IP: net.IP(local.AsSlice())}, nil)
	if err != nil { return nil, err }
	pcCtx, cancel := context.WithCancel(t.ctx)
	return &tailnetPacketConn{PacketConn: pc, server: client, ctx: pcCtx,
		cancel: cancel, network: networkName, writeDeadline: pipe.MakePipeDeadline()}, nil
}

func (t *Tailscale) PacketConnPacket(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	return t.PacketConn(ctx, addr)
}

func (t *Tailscale) Ping(ctx context.Context, addr netapi.Address) (uint64, error) {
	client, err := t.ready(ctx)
	if err != nil { return 0, err }
	ip, err := resolveAddr(ctx, client, "tcp", addr)
	if err != nil { return 0, err }
	ctx, cancel := context.WithTimeout(ctx, configuration.Timeout)
	defer cancel()
	stop := context.AfterFunc(t.ctx, cancel)
	defer stop()
	latency, err := client.Ping(ctx, ip.Addr())
	return uint64(latency), err
}

func awaitPing(ctx context.Context, ping func(func(*ipnstate.PingResult))) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	ch := make(chan *ipnstate.PingResult, 1)
	ping(func(r *ipnstate.PingResult) {
		select {
		case ch <- r:
		default:
		}
	})
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case r := <-ch:
		if r == nil {
			return 0, errors.New("tailscale ping returned no result")
		}
		if r.Err != "" {
			return 0, fmt.Errorf("tailscale ping failed: %s", r.Err)
		}
		return uint64(r.LatencySeconds * float64(time.Second)), nil
	}
}

// tailnetPacketConn is a real unconnected socket. Every destination is checked
// and resolved through this server; ordinary names cannot escape to host sockets.
type tailnetPacketConn struct {
	net.PacketConn
	server        *lite.Client
	ctx           context.Context
	network       string
	cancel        context.CancelFunc
	writeDeadline pipe.PipeDeadline
}

func (p *tailnetPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
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
	ip, err := resolveAddr(ctx, p.server, p.network, a)
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

func (p *tailnetPacketConn) Close() error {
	p.cancel()
	p.writeDeadline.Set(time.Time{})
	return p.PacketConn.Close()
}
func (p *tailnetPacketConn) SetWriteDeadline(t time.Time) error {
	if p.ctx.Err() != nil {
		return net.ErrClosed
	}
	p.writeDeadline.Set(t)
	return p.PacketConn.SetWriteDeadline(t)
}
func (p *tailnetPacketConn) SetDeadline(t time.Time) error {
	if err := p.SetReadDeadline(t); err != nil {
		return err
	}
	return p.SetWriteDeadline(t)
}

// migrateState preserves existing node identity when adopting hashed state
// directories. Already-migrated configurations are never overwritten.
func migrateState(base, dir, hostname string) error {
	if _, err := os.Lstat(dir); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if hostname == "" {
		// The old empty-hostname configuration stored state in the tailscale root.
		old := filepath.Join(base, "tailscale", "tailscaled.state")
		if _, err := os.Lstat(old); errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			return err
		}
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		return os.Rename(old, filepath.Join(dir, "tailscaled.state"))
	}
	if hostname == "." || hostname == ".." || filepath.Base(hostname) != hostname {
		return nil
	}
	old := filepath.Join(base, "tailscale", hostname)
	info, err := os.Lstat(old)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("tailscale legacy state path is not a directory")
	}
	return os.Rename(old, dir)
}
