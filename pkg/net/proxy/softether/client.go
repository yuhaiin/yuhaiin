// Package softether implements SoftEther's native SSL-VPN outbound over TLS.
// It is not SSTP. The protocol carries Ethernet; this adapter uses a
// virtual Ethernet endpoint and yuhaiin's existing in-process gVisor IP stack.
package softether

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/softether/native"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

type Config struct {
	AuthType           string
	ClientCertPEM      string
	ClientKeyPEM       string
	IPv6Address        string
	IPv6Router         string
	UDPAcceleration    bool
	AutoReconnect      bool
	Gateway            string
	Username           string
	Password           string
	Hub                string
	CACertPEM          string
	InsecureSkipVerify bool
	// Address is an optional static client IPv4 prefix, such as 192.168.30.25/24.
	// When empty, DHCP is required on the SoftEther virtual hub.
	Address string
	// Router is the IPv4 address of the next-hop on the virtual hub.
	// It is required for static addressing; DHCP determines it automatically.
	Router string
	MTU    int
}

type Client struct {
	netapi.EmptyDispatch
	session     *native.ClientSession
	network     *wireguard.NetTun
	mac         macAddr
	gatewayMAC  macAddr
	gatewayMAC6 macAddr
	ipv6        netip.Addr
	router6     netip.Addr
	ip          netip.Addr
	router      netip.Addr
	mtu         int
	ctx         context.Context
	cancel      context.CancelFunc
	once        sync.Once
	running     atomic.Bool
	tcp         *dialer.HappyEyeballsv2Dialer[*gonet.TCPConn]
	accel       *udpAcceleration
}

var _ netapi.Proxy = (*Client)(nil)

func init() {
	register.RegisterContractPoint("softether", func(cfg contractnode.SoftEther, p netapi.Proxy) (netapi.Proxy, error) {
		return NewOutbound(Config{
			Gateway: cfg.Gateway, Username: cfg.Username, Password: cfg.Password,
			Hub: cfg.Hub, CACertPEM: cfg.CACertPEM, InsecureSkipVerify: cfg.InsecureSkipVerify,
			Address: cfg.Address, Router: cfg.Router, MTU: int(cfg.MTU),
			AuthType: cfg.AuthType, ClientCertPEM: cfg.ClientCertPEM, ClientKeyPEM: cfg.ClientKeyPEM, IPv6Address: cfg.IPv6Address, IPv6Router: cfg.IPv6Router, UDPAcceleration: cfg.UDPAcceleration, AutoReconnect: cfg.AutoReconnect,
		}, p)
	})
}

func gatewayAddress(input string) (host, endpoint string, err error) {
	if input == "" || strings.ContainsAny(input, "/?#@") || strings.Contains(input, "://") {
		return "", "", errors.New("softether: gateway must be hostname or IP with optional port")
	}
	if h, p, e := net.SplitHostPort(input); e == nil {
		if h == "" {
			return "", "", errors.New("softether: missing gateway hostname")
		}
		n, e := strconv.ParseUint(p, 10, 16)
		if e != nil || n == 0 {
			return "", "", errors.New("softether: invalid gateway port")
		}
		return h, net.JoinHostPort(h, p), nil
	}
	// Treat a bare IPv6 address as a hostname without a port.
	h := strings.Trim(input, "[]")
	if h == "" || strings.Contains(h, ":") && net.ParseIP(h) == nil {
		return "", "", errors.New("softether: invalid gateway address")
	}
	return h, net.JoinHostPort(h, "443"), nil
}

func NewClient(cfg Config, upstream netapi.Proxy) (*Client, error) {
	return newClientContext(context.Background(), cfg, upstream)
}

func newClientContext(parent context.Context, cfg Config, upstream netapi.Proxy) (*Client, error) {
	host, endpoint, err := gatewayAddress(cfg.Gateway)
	if err != nil {
		return nil, err
	}
	if cfg.Username == "" {
		return nil, errors.New("softether: username required")
	}
	if cfg.AuthType == "" {
		cfg.AuthType = "password"
	}
	switch cfg.AuthType {
	case "password":
		if cfg.Password == "" {
			return nil, errors.New("softether: password required")
		}
	case "certificate":
		if cfg.ClientCertPEM == "" || cfg.ClientKeyPEM == "" {
			return nil, errors.New("softether: certificate and RSA private key required")
		}
	default:
		return nil, fmt.Errorf("softether: unknown auth type %q", cfg.AuthType)
	}
	if cfg.Hub == "" {
		cfg.Hub = "DEFAULT"
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1400
	}
	if cfg.MTU < 576 || cfg.MTU > 1500 {
		return nil, fmt.Errorf("softether: invalid MTU %d", cfg.MTU)
	}
	if (cfg.Address == "") != (cfg.Router == "") {
		return nil, errors.New("softether: static address and router must be provided together")
	}
	if (cfg.IPv6Address == "") != (cfg.IPv6Router == "") {
		return nil, errors.New("softether: IPv6 address and router must be supplied together")
	}
	var ipv6Prefix netip.Prefix
	var ipv6Router netip.Addr
	if cfg.IPv6Address != "" {
		if cfg.MTU < 1280 {
			return nil, errors.New("softether: IPv6 MTU must be at least 1280")
		}
		var e error
		ipv6Prefix, e = netip.ParsePrefix(cfg.IPv6Address)
		if e != nil || !ipv6Prefix.Addr().Is6() || ipv6Prefix.Addr().IsUnspecified() || ipv6Prefix.Addr().IsMulticast() {
			return nil, errors.New("softether: invalid static IPv6 prefix")
		}
		ipv6Router, e = netip.ParseAddr(cfg.IPv6Router)
		if e != nil || !ipv6Router.Is6() || ipv6Router.IsUnspecified() || ipv6Router.IsMulticast() {
			return nil, errors.New("softether: invalid IPv6 router")
		}
	}
	var static lease
	if cfg.Address != "" {
		prefix, e := netip.ParsePrefix(cfg.Address)
		if e != nil || !prefix.Addr().Is4() {
			return nil, errors.New("softether: invalid static IPv4 prefix")
		}
		router, e := netip.ParseAddr(cfg.Router)
		if e != nil || !router.Is4() {
			return nil, errors.New("softether: invalid IPv4 router")
		}
		static = lease{ip: prefix.Addr(), router: router, mask: prefix.Bits()}
	}

	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if cfg.CACertPEM != "" && !roots.AppendCertsFromPEM([]byte(cfg.CACertPEM)) {
		return nil, errors.New("softether: invalid CA PEM")
	}
	tlsConf := &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS12,
		InsecureSkipVerify: cfg.InsecureSkipVerify} //nolint:gosec // explicit user opt-in
	ctx, cancel := context.WithTimeout(parent, 25*time.Second)
	defer cancel()
	a, err := netapi.ParseAddress("tcp", endpoint)
	if err != nil {
		return nil, err
	}
	var raw net.Conn
	if upstream != nil && !register.IsZero(upstream) {
		raw, err = upstream.Conn(ctx, a)
	} else {
		raw, err = dialer.DialHappyEyeballsv1(ctx, a)
	}
	if err != nil {
		return nil, fmt.Errorf("softether: transport: %w", err)
	}
	clientCert, clientKey := "", ""
	if cfg.AuthType == "certificate" {
		clientCert, clientKey = cfg.ClientCertPEM, cfg.ClientKeyPEM
	}
	// A UDP socket is created before login because the server needs our port/key.
	// Using UDP via a TCP-only upstream proxy could silently leak traffic.
	var udpConn net.PacketConn
	var udpOpts *native.UDPClientOptions
	if cfg.UDPAcceleration {
		if upstream != nil && !register.IsZero(upstream) {
			_ = raw.Close()
			return nil, errors.New("softether: UDP acceleration through a chained proxy is unsupported")
		}
		udpConn, err = dialer.ListenPacket(ctx, "udp", "", nil)
		if err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("softether: UDP bind: %w", err)
		}
		defer func() {
			if udpConn != nil {
				_ = udpConn.Close()
			}
		}()
		local, ok := udpConn.LocalAddr().(*net.UDPAddr)
		if !ok || local.Port <= 0 || local.Port > 65535 {
			_ = raw.Close()
			return nil, errors.New("softether: invalid UDP local address")
		}
		udpOpts = &native.UDPClientOptions{Port: uint16(local.Port)}
		if _, err = rand.Read(udpOpts.KeyV2[:]); err != nil {
			_ = raw.Close()
			return nil, err
		}
		if _, err = rand.Read(udpOpts.KeyV1[:]); err != nil {
			_ = raw.Close()
			return nil, err
		}
	}
	remoteIP := net.IP(nil)
	if ra, ok := raw.RemoteAddr().(*net.TCPAddr); ok {
		remoteIP = ra.IP
	}
	session, err := native.ConnectWithOptions(ctx, raw, tlsConf, host, cfg.Username, cfg.Password, cfg.Hub, clientCert, clientKey, udpOpts)
	if err != nil {
		return nil, err
	}
	// From this point on, every failure must close the TLS session.
	mac, err := randomMAC()
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	l := static
	if !l.ip.Is4() {
		l, err = negotiateDHCP(session, mac, 10*time.Second)
		if err != nil {
			_ = session.Close()
			return nil, err
		}
	}
	nextHop, err := resolveGateway(session, mac, l.ip, l.router, 7*time.Second)
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	prefixes := []netip.Prefix{netip.PrefixFrom(l.ip, l.mask)}
	var nextHop6 macAddr
	if ipv6Prefix.IsValid() {
		nextHop6, err = resolveIPv6Router(session, mac, ipv6Prefix.Addr(), ipv6Router, 7*time.Second)
		if err != nil {
			_ = session.Close()
			return nil, err
		}
		prefixes = append(prefixes, ipv6Prefix)
	}
	network, err := wireguard.CreateNetTUN(prefixes, cfg.MTU)
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	runCtx, runCancel := context.WithCancel(context.Background())
	c := &Client{session: session, network: network, mac: mac, gatewayMAC: nextHop,
		ip: l.ip, router: l.router, mtu: cfg.MTU, ctx: runCtx, cancel: runCancel,
		ipv6: ipv6Prefix.Addr(), router6: ipv6Router, gatewayMAC6: nextHop6}
	c.tcp = dialer.NewHappyEyeballsv2Dialer(func(ctx context.Context, ip net.IP, port uint16) (*gonet.TCPConn, error) {
		return network.DialContextTCP(ctx, &net.TCPAddr{IP: ip, Port: int(port)})
	})
	if udpConn != nil && session.UDPOptions() != nil {
		udpSettings := session.UDPOptions()
		peer := remoteIP
		if udpSettings.ServerIP != nil && !udpSettings.ServerIP.IsUnspecified() {
			peer = udpSettings.ServerIP
		}
		accel, e := newUDPAcceleration(udpConn, peer, udpOpts, udpSettings)
		if e == nil {
			c.accel = accel
			udpConn = nil // The running Client now owns this socket.
		}
	}
	c.running.Store(true)
	if c.accel != nil {
		go c.accel.run(c.ctx.Done(), c.deliverUDP)
	}
	go c.receive()
	go c.transmit()
	go c.keepAlive()
	return c, nil
}

func (c *Client) receive() {
	for {
		frame, err := c.session.ReadFrame()
		if err != nil {
			go c.Close()
			return
		}
		if len(frame) < 14 {
			continue
		}
		dst := frame[:6]
		if !equalMAC(dst, c.mac[:]) && !broadcastMAC(dst) && !(len(dst) == 6 && dst[0] == 0x33 && dst[1] == 0x33) {
			continue
		}
		switch uint16(frame[12])<<8 | uint16(frame[13]) {
		case etherARP:
			op, from, src, target, ok := parseARP(frame)
			if ok && op == 1 && target == c.ip {
				if e := c.session.WriteFrame(buildARP(c.mac, c.ip, src, from, 2)); e != nil {
					go c.Close()
					return
				}
			}
		case etherIPv6:
			if !c.ipv6.Is6() {
				continue
			}
			typ, target, src, _, from, ok := parseNeighborMessage(frame)
			if ok && typ == 135 && target == c.ipv6 && src.Is6() && !src.IsUnspecified() {
				if err := c.session.WriteFrame(neighborAdvertise(c.mac, from, c.ipv6, src)); err != nil {
					go c.Close()
					return
				}
				continue
			}
			pkt := frame[14:]
			if len(pkt) == 0 || pkt[0]>>4 != 6 || !equalMAC(dst, c.mac[:]) {
				continue
			}
			if _, err := c.network.Write([][]byte{pkt}, 0); err != nil {
				go c.Close()
				return
			}
		case etherIPv4:
			pkt := frame[14:]
			if len(pkt) == 0 || pkt[0]>>4 != 4 {
				continue
			}
			if _, err := c.network.Write([][]byte{pkt}, 0); err != nil {
				go c.Close()
				return
			}
		}
	}
}

func equalMAC(a, b []byte) bool {
	if len(a) != 6 || len(b) != 6 {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func broadcastMAC(a []byte) bool {
	if len(a) != 6 {
		return false
	}
	for _, v := range a {
		if v != 255 {
			return false
		}
	}
	return true
}

func (c *Client) transmit() {
	buf := make([]byte, c.mtu+2*tun.ReadPacketSpacing)
	packets := make([]tun.ReadPacket, 1)
	for {
		n, err := c.network.Read(buf, packets)
		if err != nil {
			go c.Close()
			return
		}
		for _, p := range packets[:n] {
			if p.Size == 0 || p.Offset < 0 || p.Offset+p.Size > len(buf) {
				continue
			}
			ip := buf[p.Offset : p.Offset+p.Size]
			var ethertype uint16
			var dst macAddr
			switch ip[0] >> 4 {
			case 4:
				ethertype, dst = etherIPv4, c.gatewayMAC
			case 6:
				if !c.ipv6.Is6() {
					continue
				}
				ethertype, dst = etherIPv6, c.gatewayMAC6
			default:
				continue
			}
			frame := ethernetFrame(dst, c.mac, ethertype, ip)
			if c.accel != nil && c.accel.ready() && len(frame) <= 1350 {
				if err := c.accel.send(frame); err == nil {
					continue
				}
			}
			if err := c.session.WriteFrame(frame); err != nil {
				go c.Close()
				return
			}
		}
	}
}

func (c *Client) keepAlive() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			if err := c.session.WriteKeepAlive(); err != nil {
				go c.Close()
				return
			}
		}
	}
}

func (c *Client) Conn(ctx context.Context, address netapi.Address) (net.Conn, error) {
	if !c.running.Load() {
		return nil, net.ErrClosed
	}
	conn, err := c.tcp.DialHappyEyeballsv2(ctx, address)
	if err != nil {
		return nil, err
	}
	return wireguard.NewWrapGoNetTcpConn(conn), nil
}

func (c *Client) PacketConn(ctx context.Context, destination netapi.Address) (net.PacketConn, error) {
	if !c.running.Load() {
		return nil, net.ErrClosed
	}
	var bind *net.UDPAddr
	if destination != nil {
		if ipaddr, ok := destination.(netapi.IPAddress); ok && ipaddr.AddrPort().Addr().Is4() {
			bind = &net.UDPAddr{IP: net.IPv4zero}
		}
	}
	if bind == nil && !c.ipv6.Is6() {
		bind = &net.UDPAddr{IP: net.IPv4zero}
	}
	conn, err := c.network.DialUDP(bind, nil)
	if err != nil {
		return nil, err
	}
	return wireguard.NewWrapGoNetUdpConn(context.WithoutCancel(ctx), conn), nil
}

func (c *Client) Ping(context.Context, netapi.Address) (uint64, error) {
	return 0, errors.New("softether: ICMP ping is not implemented")
}

func (c *Client) Close() error {
	var err error
	c.once.Do(func() {
		c.running.Store(false)
		c.cancel()
		err = errors.Join(c.session.Close(), c.network.Close())
		if c.accel != nil {
			err = errors.Join(err, c.accel.sock.Close())
		}
	})
	return err
}

// deliverUDP processes authenticated Ethernet frames from UDP acceleration.
// The protocol never interprets UDP datagrams as raw application UDP payloads.
func (c *Client) deliverUDP(frame []byte) {
	if len(frame) < 14 {
		return
	}
	dst := frame[:6]
	if !equalMAC(dst, c.mac[:]) && !broadcastMAC(dst) && !(dst[0] == 0x33 && dst[1] == 0x33) {
		return
	}
	switch uint16(frame[12])<<8 | uint16(frame[13]) {
	case etherARP:
		op, from, src, target, ok := parseARP(frame)
		if ok && op == 1 && target == c.ip {
			_ = c.session.WriteFrame(buildARP(c.mac, c.ip, src, from, 2))
		}
	case etherIPv4:
		if len(frame) > 14 && frame[14]>>4 == 4 {
			_, _ = c.network.Write([][]byte{frame[14:]}, 0)
		}
	case etherIPv6:
		if !c.ipv6.Is6() {
			return
		}
		typ, target, src, _, from, ok := parseNeighborMessage(frame)
		if ok && typ == 135 && target == c.ipv6 && !src.IsUnspecified() {
			_ = c.session.WriteFrame(neighborAdvertise(c.mac, from, c.ipv6, src))
			return
		}
		if len(frame) > 14 && frame[14]>>4 == 6 && equalMAC(dst, c.mac[:]) {
			_, _ = c.network.Write([][]byte{frame[14:]}, 0)
		}
	}
}
