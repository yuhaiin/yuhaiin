package tailscale

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	mdns "github.com/miekg/dns"
	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/netns"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/types/nettype"
)

type hijackDialer struct{}

func (d hijackDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d hijackDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	ad, err := netapi.ParseAddress(network, address)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, configuration.Timeout)
	defer cancel()

	store := netapi.WithContext(ctx)
	store.SetComponent("tailscale")

	return configuration.ProxyChain.Conn(store, ad)
}

type hijackListener struct{}

func (l hijackListener) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return dialer.ListenContext(ctx, network, address)
}

func (l hijackListener) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	store := netapi.WithContext(ctx)
	store.ConnOptions().
		SetRouteMode(config.Mode_direct).
		SetBindAddress(address)
	store.SetComponent("tailscale").
		SetDomainString("tailscale-" + network + "-listener" + address).
		SetIPString(address)

	pc, err := configuration.ProxyChain.PacketConn(store, netapi.DomainAddr{
		AddressNetwork: netapi.ParseAddressNetwork(network),
	})
	if err != nil {
		return nil, err
	}

	return &nettypePacketConn{pc}, nil
}

var _ nettype.PacketConn = (*nettypePacketConn)(nil)

type nettypePacketConn struct {
	net.PacketConn
}

func (p *nettypePacketConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	return p.PacketConn.WriteTo(b, net.UDPAddrFromAddrPort(addr))
}

func (p *nettypePacketConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	n, addr, err := p.PacketConn.ReadFrom(b)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	ad, err := netapi.ParseSysAddr(addr)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	if ad.IsFqdn() {
		return 0, netip.AddrPort{}, fmt.Errorf("address: %s is not ip address", ad.Hostname())
	}

	return n, ad.(netapi.IPAddress).AddrPort(), nil
}

type hijackResolver struct{}

func (hijackResolver) LookupIP(ctx context.Context, domain string, opts ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
	return configuration.ResolverChain.LookupIP(ctx, domain, opts...)
}

func (hijackResolver) Raw(ctx context.Context, req mdns.Question) (mdns.Msg, error) {
	return configuration.ResolverChain.Raw(ctx, req)
}

func (hijackResolver) Close() error { return nil }

func (hijackResolver) Name() string { return "tailscale-hijack-resolver" }

var Mux atomic.Pointer[http.ServeMux]

type instance struct {
	authKey    string
	hostname   string
	controlUrl string
}

var instanceStore = lru.NewSyncLru(lru.WithCapacity[instance, *Tailscale](100))

func init() {
	register.RegisterPoint(New)
	netns.SetWrapDialer(func(d netns.Dialer) netns.Dialer { return hijackDialer{} })
	netns.SetWrapListener(func(li netns.ListenerInterface) netns.ListenerInterface { return hijackListener{} })
	dnscache.Get().Forward = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return netapi.NewDnsConn(hijackResolver{}), nil
		},
	}
	// disable portmapper for tailscale, this is a global setting
	// on my macbook, portmapper will make nat travel faild, so disable it
	//
	// mybe some tailscale bug, we need more test
	envknob.Setenv("TS_DISABLE_PORTMAPPER", "true")
	envknob.Setenv("TS_DISABLE_UPNP", "true")
	envknob.Setenv("TS_ENABLE_RAW_DISCO", "false")
	// envknob.SetNoLogsNoSupport()
}

type Tailscale struct {
	netapi.EmptyDispatch
	dialer     netapi.Proxy
	tsnet      *tsnet.Server
	authKey    string
	hostname   string
	controlUrl string
	mu         sync.RWMutex
	debug      atomic.Bool
}

func New(c *node.Tailscale, dialer netapi.Proxy) (netapi.Proxy, error) {
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

func (t *Tailscale) resolveAddr(dialer *tsnet.Server, addr netapi.Address) (netip.AddrPort, error) {
	if !addr.IsFqdn() {
		return addr.(netapi.IPAddress).AddrPort(), nil
	}

	dnsmap := dialer.Sys().Dialer.Get().GetDNSMap()
	if dnsmap == nil {
		return netip.AddrPort{}, fmt.Errorf("tailscale dns map is nil")
	}

	ad, ok := dnsmap[strings.ToLower(addr.Hostname())]
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("tailscale dns map missing %s", addr.Hostname())
	}

	naddr := netip.AddrPortFrom(ad, addr.Port())

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

	_, err = dialer.Up(ctx)
	if err != nil {
		return nil, err
	}

	// see: https://github.com/tailscale/tailscale/issues/10860
	//      https://github.com/tailscale/tailscale/issues/4677
	//
	// the magic dns is not working on tsnet, so we need hijack it
	if addr.Port() == 53 {
		if hostname := addr.Hostname(); hostname == tsaddr.TailscaleServiceIP().String() || hostname == tsaddr.TailscaleServiceIPv6().String() {
			src, dst := pipe.Pipe()
			go func() {
				defer src.Close()
				t.tsnet.Sys().DNSManager.Get().HandleTCPConn(src, netip.AddrPort{})
			}()
			return dst, nil
		}
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

	states, err := dialer.Up(ctx)
	if err != nil {
		return nil, err
	}

	var laddr netip.Addr

	for _, ip := range states.TailscaleIPs {
		if !addr.IsFqdn() && addr.(netapi.IPAddress).AddrPort().Addr().Is4() {
			if ip.Is4() {
				laddr = ip
			}
		} else {
			if ip.Is6() {
				laddr = ip
			}
		}
	}

	if !laddr.IsValid() {
		return nil, fmt.Errorf("tailscale ip not found")
	}

	conn, err := dialer.ListenPacket("udp", net.JoinHostPort(laddr.String(), "0"))
	if err != nil {
		return nil, err
	}

	return &warpPacketConn{ctx: context.WithoutCancel(ctx), PacketConn: conn}, nil
}

var (
	tailscaleServiceIP   = tsaddr.TailscaleServiceIP()
	tailscaleServiceIPv6 = tsaddr.TailscaleServiceIPv6()
)

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

	_, err = dialer.Up(ctx)
	if err != nil {
		return nil, err
	}

	// see: https://github.com/tailscale/tailscale/issues/10860
	//      https://github.com/tailscale/tailscale/issues/4677
	//
	// the magic dns is not working on tsnet, so we need hijack it
	if !addr.IsFqdn() && addr.Port() == 53 {
		ipaddr := addr.(netapi.IPAddress).AddrPort().Addr().Unmap()
		if ipaddr == tailscaleServiceIP || ipaddr == tailscaleServiceIPv6 {
			return NewDnsPacket(dialer.Sys().Dialer.Get(), ipaddr), nil
		}
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

func (t *Tailscale) Ping(ctx context.Context, addr netapi.Address) (uint64, error) {
	dialer, err := t.init(ctx)
	if err != nil {
		return 0, err
	}

	defer func() {
		if err := recover(); err != nil {
			log.Error("tailscale packet conn panic", "err", err)
		}
	}()

	_, err = dialer.Up(ctx)
	if err != nil {
		return 0, err
	}

	nip, err := t.resolveAddr(dialer, addr)
	if err != nil {
		return 0, err
	}

	var resp uint64
	dialer.Sys().Engine.Get().Ping(nip.Addr(),
		tailcfg.PingICMP, 8, func(pr *ipnstate.PingResult) {
			if pr.Err != "" {
				err = fmt.Errorf("tailscale ping failed: %s", pr.Err)
			}
			resp = uint64(pr.LatencySeconds)
		})

	return resp, err
}

type warpPacketConn struct {
	ctx context.Context
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

	var udpAddr *net.UDPAddr
	if !a.IsFqdn() {
		udpAddr = net.UDPAddrFromAddrPort(a.(netapi.IPAddress).AddrPort())
	} else {
		ctx, cancel := context.WithTimeout(w.ctx, configuration.ResolverTimeout)
		ips, err := netapi.ResolverIP(ctx, a.Hostname())
		cancel()
		if err != nil {
			return 0, err
		}
		udpAddr = ips.RandUDPAddr(a.Port())
	}

	return w.PacketConn.WriteTo(buf, udpAddr)
}

func (w *warpPacketConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	n, addr, err := w.PacketConn.ReadFrom(buf)
	return n, addr, err
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

type dnsPacket struct {
	cancel        context.CancelFunc
	ctx           context.Context
	ch            chan []byte
	writeDeadline pipe.PipeDeadline
	readDeadline  pipe.PipeDeadline
	dialer        *tsdial.Dialer
	src           netip.Addr
}

func NewDnsPacket(dialer *tsdial.Dialer, src netip.Addr) net.PacketConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &dnsPacket{
		cancel:        cancel,
		ctx:           ctx,
		ch:            make(chan []byte, 100),
		writeDeadline: pipe.MakePipeDeadline(),
		readDeadline:  pipe.MakePipeDeadline(),
		dialer:        dialer,
		src:           src,
	}
}

func (d *dnsPacket) Close() error {
	d.cancel()
	return nil
}

func (d *dnsPacket) ReadFrom(buf []byte) (int, net.Addr, error) {
	select {
	case <-d.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	case <-d.ctx.Done():
		return 0, nil, d.ctx.Err()
	case b := <-d.ch:
		n := copy(buf, b)
		pool.PutBytes(b)
		return n, &net.UDPAddr{
			IP:   d.src.AsSlice(),
			Port: 53,
		}, nil
	}
}

func (d *dnsPacket) WriteTo(buf []byte, addr net.Addr) (int, error) {
	var msg mdns.Msg
	if err := msg.Unpack(buf); err != nil {
		return 0, err
	}

	if len(msg.Question) == 0 {
		return len(buf), nil
	}

	msg.Response = true

	if msg.Question[0].Qtype == mdns.TypeA {
		q := msg.Question[0]
		name := strings.TrimSuffix(q.Name, ".")

		if ip, ok := d.dialer.GetDNSMap()[name]; ok {
			msg.Answer = []mdns.RR{
				&mdns.A{
					Hdr: mdns.RR_Header{
						Name:   q.Name,
						Ttl:    20,
						Class:  mdns.ClassINET,
						Rrtype: mdns.TypeA,
					},
					A: ip.AsSlice(),
				},
			}
		}
	}

	data, err := msg.Pack()
	if err != nil {
		return 0, err
	}

	select {
	case <-d.writeDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	case <-d.ctx.Done():
		return 0, d.ctx.Err()
	case d.ch <- data:
		return len(buf), nil
	}
}

func (d *dnsPacket) LocalAddr() net.Addr {
	return &net.UDPAddr{
		IP: net.IPv4zero,
	}
}

func (d *dnsPacket) SetDeadline(t time.Time) error {
	_ = d.SetReadDeadline(t)
	_ = d.SetWriteDeadline(t)
	return nil
}

func (d *dnsPacket) SetReadDeadline(t time.Time) error {
	d.readDeadline.Set(t)
	return nil
}

func (d *dnsPacket) SetWriteDeadline(t time.Time) error {
	d.writeDeadline.Set(t)
	return nil
}
