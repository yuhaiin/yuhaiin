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
	"golang.org/x/sync/singleflight"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/dns"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/tsnet"
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
	tsnet    *tsnet.Server
	closed   bool
	stateDir string
	sf       singleflight.Group
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

func (t *Tailscale) init(ctx context.Context) (*tsnet.Server, error) {
	if err := checkLoop(ctx, t); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if netapi.IsBackgroundProbe(ctx) {
		if !t.mu.TryLock() {
			return nil, netapi.ErrBackgroundProbeUnavailable
		}
	} else {
		t.mu.Lock()
	}
	defer t.mu.Unlock()
	if t.closed {
		return nil, net.ErrClosed
	}
	if t.tsnet != nil {
		return t.tsnet, nil
	}
	if netapi.IsBackgroundProbe(ctx) {
		return nil, netapi.ErrBackgroundProbeUnavailable
	}
	dir, err := statePath(configuration.DataDir.Load(), t.config)
	if err != nil {
		return nil, err
	}
	stateOwners.Lock()
	if stateOwners.paths[dir] != nil {
		stateOwners.Unlock()
		return nil, errors.New("tailscale state is already in use; close the previous node or use a distinct hostname")
	}
	stateOwners.paths[dir] = t
	stateOwners.Unlock()
	release := func() { stateOwners.Lock(); delete(stateOwners.paths, dir); stateOwners.Unlock() }
	if err := migrateState(configuration.DataDir.Load(), dir, t.config.Hostname); err != nil {
		release()
		return nil, err
	}
	u := &underlay{owner: t, ancestors: appendLoop(ctx, t)}
	s := &tsnet.Server{
		Hostname: t.config.Hostname, ControlURL: t.config.ControlURL,
		RunWebClient: true, Dir: dir, UserLogf: log.InfoFormat, Underlay: u.network(), Tun: newTailnetTun(),
	}
	if t.config.Debug {
		s.Logf = log.InfoFormat
	}
	// AuthKey is consumed synchronously during Start's one-time initialization.
	// Do not keep bootstrap credentials on the server exposed to network code.
	s.AuthKey = t.config.AuthKey
	err = s.Start()
	s.AuthKey = ""
	if err != nil {
		_ = s.Close()
		release()
		return nil, err
	}
	t.tsnet, t.stateDir = s, dir
	return s, nil
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

func (t *Tailscale) up(ctx context.Context, s *tsnet.Server) (*ipnstate.Status, error) {
	ch := t.sf.DoChan("up", func() (any, error) {
		upCtx, cancel := context.WithTimeout(t.ctx, 3*time.Minute)
		defer cancel()
		return s.Up(upCtx)
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.ctx.Done():
		return nil, net.ErrClosed
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		return res.Val.(*ipnstate.Status), nil
	}
}

func (t *Tailscale) ready(ctx context.Context) (*tsnet.Server, error) {
	s, err := t.init(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := t.up(ctx, s); err != nil {
		return nil, err
	}
	if t.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	network := s.Tun.(*tailnetTun)
	v4, v6 := s.TailscaleIPs()
	if err := network.configure(v4, v6); err != nil {
		return nil, err
	}
	network.metrics.Do(func() { serveMetrics(network) })
	return s, nil
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
	if t.tsnet != nil {
		err = t.tsnet.Close()
	}
	if t.stateDir != "" {
		stateOwners.Lock()
		delete(stateOwners.paths, t.stateDir)
		stateOwners.Unlock()
	}
	return err
}

// resolveAddr delegates MagicDNS (including family selection and ExtraRecords)
// and route classification to Tailscale. Dialing the resulting IP through
// our stack keeps the transport pinned even if a route disappears afterwards.
// Server.Dial/UserDial can fall back to a host socket on such a route change.
func resolveAddr(ctx context.Context, s *tsnet.Server, network string, addr netapi.Address) (netip.AddrPort, error) {
	sys := s.Sys()
	if sys == nil {
		return netip.AddrPort{}, errors.New("tailscale: system unavailable")
	}
	dialer, ok := sys.Dialer.GetOK()
	if !ok || dialer == nil {
		return netip.AddrPort{}, errors.New("tailscale: dialer subsystem unavailable")
	}
	ip, viaTailnet, err := dialer.UserDialPlan(ctx, network, addr.String())
	if err != nil {
		return netip.AddrPort{}, err
	}
	if !viaTailnet {
		return netip.AddrPort{}, fmt.Errorf("tailscale: destination %s has no tailnet route", addr)
	}
	return ip, nil
}

func isServiceDNS(addr netapi.Address) bool {
	if addr.IsFqdn() || addr.Port() != 53 {
		return false
	}
	ip := addr.(netapi.IPAddress).AddrPort().Addr().Unmap()
	return ip == tsaddr.TailscaleServiceIP() || ip == tsaddr.TailscaleServiceIPv6()
}

// errTailscaleDNSUnavailable indicates an incompatible Tailscale build or an
// unavailable DNS subsystem. A release built with ts_omit_dns gets a nil
// *dns.Manager even after tsnet.Up reports Running.
var errTailscaleDNSUnavailable = errors.New("tailscale: DNS manager unavailable (check ts_omit_dns build tag)")

func tailscaleDNSManager(sys *tsd.System) (*dns.Manager, error) {
	if sys == nil {
		return nil, errTailscaleDNSUnavailable
	}
	manager, ok := sys.DNSManager.GetOK()
	if !ok || manager == nil {
		return nil, errTailscaleDNSUnavailable
	}
	return manager, nil
}

func (t *Tailscale) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	s, err := t.ready(ctx)
	if err != nil {
		return nil, err
	}
	if isServiceDNS(addr) {
		manager, err := tailscaleDNSManager(s.Sys())
		if err != nil {
			return nil, err
		}
		src, dst := pipe.Pipe()
		stop := context.AfterFunc(t.ctx, func() { _ = src.Close() })
		go func() {
			defer src.Close()
			defer stop()
			manager.HandleTCPConn(src, netip.AddrPort{})
		}()
		return dst, nil
	}
	ip, err := resolveAddr(ctx, s, "tcp", addr)
	if err != nil {
		return nil, err
	}
	network, err := s.Tun.(*tailnetTun).await()
	if err != nil {
		return nil, err
	}
	return network.DialContextTCP(ctx, net.TCPAddrFromAddrPort(ip))
}

func (t *Tailscale) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	s, err := t.ready(ctx)
	if err != nil {
		return nil, err
	}
	if isServiceDNS(addr) {
		manager, err := tailscaleDNSManager(s.Sys())
		if err != nil {
			return nil, err
		}
		return newDNSPacket(t.ctx, manager.Query, addr.(netapi.IPAddress).AddrPort()), nil
	}
	ip, err := resolveAddr(ctx, s, "udp", addr)
	if err != nil {
		return nil, err
	}

	v4, v6 := s.TailscaleIPs()
	local, network := v4, "udp4"
	if ip.Addr().Is6() {
		local, network = v6, "udp6"
	}
	if !local.IsValid() {
		return nil, errors.New("tailscale has no local address for the destination family")
	}
	stack, err := s.Tun.(*tailnetTun).await()
	if err != nil {
		return nil, err
	}
	pc, err := stack.DialUDP(&net.UDPAddr{IP: net.IP(local.AsSlice())}, nil)
	if err != nil {
		return nil, err
	}
	pcCtx, pcCancel := context.WithCancel(t.ctx)
	return &tailnetPacketConn{PacketConn: pc, server: s, ctx: pcCtx, cancel: pcCancel, network: network, writeDeadline: pipe.MakePipeDeadline()}, nil
}

func (t *Tailscale) PacketConnPacket(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	return t.PacketConn(ctx, addr)
}

func (t *Tailscale) Ping(ctx context.Context, addr netapi.Address) (uint64, error) {
	s, err := t.ready(ctx)
	if err != nil {
		return 0, err
	}
	ip, err := resolveAddr(ctx, s, "tcp", addr)
	if err != nil {
		return 0, err
	}
	pingCtx, cancel := context.WithTimeout(ctx, configuration.Timeout)
	defer cancel()
	stop := context.AfterFunc(t.ctx, cancel)
	defer stop()
	sys := s.Sys()
	if sys == nil {
		return 0, errors.New("tailscale: system unavailable")
	}
	engine, ok := sys.Engine.GetOK()
	if !ok || engine == nil {
		return 0, errors.New("tailscale: engine subsystem unavailable")
	}
	return awaitPing(pingCtx, func(cb func(*ipnstate.PingResult)) {
		engine.Ping(ip.Addr(), tailcfg.PingICMP, 8, cb)
	})
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
	server        *tsnet.Server
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
