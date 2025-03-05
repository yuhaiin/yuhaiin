package tailscale

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"path"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
	"tailscale.com/envknob"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/netns"
	"tailscale.com/net/tsdial"
	"tailscale.com/tsnet"
)

var (
	dnsmapField, dnsmapFieldOk = reflect.TypeOf(&tsdial.Dialer{}).Elem().FieldByName("dns")
	dnsmapOffset               = dnsmapField.Offset
)

func init() {
	if !dnsmapFieldOk {
		panic("dnsmapField not found")
	}
}

var Mux atomic.Pointer[http.ServeMux]

type instance struct {
	authKey    string
	hostname   string
	controlUrl string
}

var (
	instanceStore = lru.NewSyncLru(lru.WithCapacity[instance, *Tailscale](100))
)

func init() {
	register.RegisterPoint(New)
	netns.SetWrapDialer(func(d netns.Dialer) netns.Dialer { return &dial{} })
	netns.SetWarpListener(func(li netns.ListenerInterface) netns.ListenerInterface { return &listener{} })
	dnscache.Get().Forward = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return netapi.NewDnsConn(ctx, dialer.Bootstrap()), nil
		},
	}
	// disable portmapper for tailscale, this is a global setting
	// on my macbook, portmapper will make nat travel faild, so disable it
	//
	// mybe some tailscale bug, we need more test
	envknob.Setenv("TS_DISABLE_PORTMAPPER", "true")
	envknob.Setenv("TS_DISABLE_UPNP", "true")
	// envknob.SetNoLogsNoSupport()
}

type Tailscale struct {
	netapi.EmptyDispatch
	dialer     netapi.Proxy
	authKey    string
	hostname   string
	controlUrl string
	tsnet      *tsnet.Server
	debug      atomic.Bool
	mu         sync.RWMutex
}

func New(c *protocol.Tailscale, dialer netapi.Proxy) (netapi.Proxy, error) {
	if c.GetAuthKey() == "" {
		return nil, fmt.Errorf("auth_key is required")
	}

	tt, _ := instanceStore.LoadOrAdd(instance{
		authKey:    c.GetAuthKey(),
		hostname:   c.GetHostname(),
		controlUrl: c.GetControlUrl(),
	}, func() *Tailscale {
		return &Tailscale{
			dialer:     dialer,
			authKey:    c.GetAuthKey(),
			hostname:   c.GetHostname(),
			controlUrl: c.GetControlUrl(),
		}
	})

	tt.debug.Store(c.GetDebug())
	if tsnet := tt.tsnet; tsnet != nil {
		if c.GetDebug() {
			tsnet.Logf = log.InfoFormat
		} else {
			tsnet.Logf = nil
		}
	}

	return tt, nil
}

func (t *Tailscale) init(context.Context) (*tsnet.Server, error) {
	t.mu.RLock()
	tsdialer := t.tsnet
	t.mu.RUnlock()
	if tsdialer != nil {
		return tsdialer, nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// make fakeip work
	// it's seem control by remote, we can't set these options here
	//
	// netns.SetBindToInterfaceByRoute(false)
	// netns.SetDisableBindConnToInterface(true)

	if t.tsnet != nil {
		return t.tsnet, nil
	}

	t.tsnet = &tsnet.Server{
		AuthKey:      t.authKey,
		Hostname:     t.hostname,
		Ephemeral:    false,
		RunWebClient: true,
		ControlURL:   t.controlUrl,
		Dir:          path.Join(configuration.DataDir.Load(), "tailscale", t.hostname),
		UserLogf:     log.InfoFormat,
	}

	if t.debug.Load() {
		t.tsnet.Logf = log.InfoFormat
	}

	if err := t.tsnet.Start(); err != nil {
		t.tsnet.Close()
		t.tsnet = nil
		return nil, err
	}

	go func() {
		lis, err := t.tsnet.Listen("tcp", ":80")
		if err != nil {
			log.Warn("tailscale listen metrics failed", "err", err)
			return
		}
		defer lis.Close()

		if err := http.Serve(lis, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if mux := Mux.Load(); mux != nil {
				mux.ServeHTTP(w, r)
			}
		})); err != nil {
			log.Warn("tailscale serve metrics failed", "err", err)
		}
	}()

	return t.tsnet, nil
}

func (t *Tailscale) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.tsnet != nil {
		t.tsnet.Close()
		t.tsnet = nil
	}

	return nil
}

func (t *Tailscale) waitAddr(ctx context.Context, tsnet *tsnet.Server) (netip.Addr, netip.Addr, error) {
	for {
		ipv4, ipv6 := tsnet.TailscaleIPs()

		if ipv4.IsValid() || ipv6.IsValid() {
			return ipv4, ipv6, nil
		}

		log.Info("tailscale wait addr")

		select {
		case <-ctx.Done():
			return netip.Addr{}, netip.Addr{}, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func (t *Tailscale) resolveAddr(dialer *tsnet.Server, addr netapi.Address) (netip.AddrPort, error) {
	if !addr.IsFqdn() {
		ad, _ := netip.AddrFromSlice(addr.(netapi.IPAddress).IP())
		return netip.AddrPortFrom(ad, addr.Port()), nil
	}

	dd := dialer.Sys().Dialer.Get()
	dnsmap := *(*map[string]netip.Addr)(unsafe.Pointer(uintptr(unsafe.Pointer(dd)) + dnsmapOffset))

	if dnsmap == nil {
		return netip.AddrPort{}, fmt.Errorf("tailscale dns map is nil")
	}

	ad, ok := dnsmap[strings.ToLower(addr.Hostname())]
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("tailscale dns map missing %s", addr.Hostname())
	}

	naddr := netip.AddrPortFrom(ad, addr.Port())

	log.Info("resolve dns", "addr", naddr, "domain", addr, "net", addr.Network())

	return naddr, nil
}

func (t *Tailscale) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	dialer, err := t.init(ctx)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := recover(); err != nil {
			log.Error("tailscale conn panic", "err", err)
		}
	}()

	_, _, err = t.waitAddr(ctx, dialer)
	if err != nil {
		return nil, err
	}

	nip, err := t.resolveAddr(dialer, addr)
	if err != nil {
		return nil, err
	}

	conn, err := dialer.Sys().Dialer.Get().NetstackDialTCP(ctx, nip)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func (t *Tailscale) PacketConnPacket(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	dialer, err := t.init(ctx)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := recover(); err != nil {
			log.Error("tailscale packet conn panic", "err", err)
		}
	}()

	ipv4, ipv6, err := t.waitAddr(ctx, dialer)
	if err != nil {
		return nil, err
	}

	laddr := ipv6
	if !addr.IsFqdn() && addr.(netapi.IPAddress).IP().To4() != nil {
		laddr = ipv4
	}

	conn, err := dialer.ListenPacket("udp", net.JoinHostPort(laddr.String(), "0"))
	if err != nil {
		return nil, err
	}

	return &warpPacketConn{ctx: context.WithoutCancel(ctx), ts: t, PacketConn: conn}, nil
}

func (t *Tailscale) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	dialer, err := t.init(ctx)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := recover(); err != nil {
			log.Error("tailscale packet conn panic", "err", err)
		}
	}()

	_, _, err = t.waitAddr(ctx, dialer)
	if err != nil {
		return nil, err
	}

	nip, err := t.resolveAddr(dialer, addr)
	if err != nil {
		return nil, err
	}

	// tailscale tsnet only support dial udp, listenPacket will error with "endpoint is in invalid state"
	conn, err := dialer.Sys().Dialer.Get().NetstackDialUDP(ctx, nip)
	if err != nil {
		return nil, err
	}

	return &warpUDPConn{ctx: context.WithoutCancel(ctx), ts: t, addr: addr, Conn: conn}, nil
}

type warpPacketConn struct {
	ctx context.Context
	ts  *Tailscale
	net.PacketConn
}

func (c *warpPacketConn) Close() error {
	return c.PacketConn.Close()
}

func (w *warpPacketConn) WriteTo(buf []byte, addr net.Addr) (int, error) {
	a, err := netapi.ParseSysAddr(addr)
	if err != nil {
		return 0, err
	}

	ur, err := dialer.ResolveUDPAddr(w.ctx, a)
	if err != nil {
		return 0, err
	}

	return w.PacketConn.WriteTo(buf, ur)
}

var _ net.PacketConn = (*warpUDPConn)(nil)

type warpUDPConn struct {
	ctx  context.Context
	ts   *Tailscale
	addr net.Addr
	net.Conn
}

func (w *warpUDPConn) WriteTo(buf []byte, addr net.Addr) (int, error) {
	return w.Conn.Write(buf)
}

func (w *warpUDPConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	n, err := w.Conn.Read(buf)
	return n, w.addr, err
}

type dial struct{}

func (d *dial) Dial(network, address string) (net.Conn, error) {
	// log.Info("tailscale dial", "network", network, "address", address)
	return d.DialContext(context.Background(), network, address)
}

func (d *dial) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	ad, err := netapi.ParseAddress(network, address)
	// log.Info("tailscale dial", "network", network, "address", address, "netapi Addr", ad, "err", err)
	if err == nil {
		return dialer.DialHappyEyeballsv2(ctx, ad)
	}

	return dialer.DialContext(ctx, network, address)
}

type listener struct{}

func (l *listener) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	// log.Info("tailscale listen", "network", network, "address", address)
	return dialer.ListenContext(ctx, network, address)
}

func (l *listener) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	// _, file, line, _ := runtime.Caller(2)
	// log.Info("tailscale listen packet", "network", network, "address", address, "file", file, "line", line)
	return dialer.ListenPacket(ctx, network, address)
}
