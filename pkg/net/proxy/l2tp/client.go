// Package l2tp exposes native userspace L2TP tunnels as a yuhaiin outbound.
package l2tp

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/l2tp/native"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

type Config struct {
	native.Config
	LocalAddress                string
	AutoReconnect               bool
	Address, Router, IPv6Router string
}

type Client struct {
	netapi.EmptyDispatch
	session *native.Session
	network tunnelNetwork
	tcp     *dialer.HappyEyeballsv2Dialer[*gonet.TCPConn]
	once    sync.Once
	ctx     context.Context
	cancel  context.CancelFunc
	cfg     Config
	wg      sync.WaitGroup
}

var _ netapi.Proxy = (*Client)(nil)

func init() {
	register.RegisterContractPoint("l2tp", func(cfg contractnode.L2TP, upstream netapi.Proxy) (netapi.Proxy, error) {
		return NewOutbound(Config{Version: 2, AuthType: cfg.AuthType, Gateway: cfg.Gateway, Username: cfg.Username, Password: cfg.Password, SharedSecret: cfg.SharedSecret, Hostname: cfg.Hostname, MTU: int(cfg.MTU), IPv6: cfg.IPv6, IPv6Address: cfg.IPv6Address, AutoReconnect: cfg.AutoReconnect}, upstream)
	})
	register.RegisterContractPoint("l2tpv3", func(cfg contractnode.L2TPv3, upstream netapi.Proxy) (netapi.Proxy, error) {
		local, err := hex.DecodeString(cfg.LocalCookie)
		if err != nil {
			return nil, fmt.Errorf("l2tpv3: local cookie: %w", err)
		}
		peer, err := hex.DecodeString(cfg.PeerCookie)
		if err != nil {
			return nil, fmt.Errorf("l2tpv3: peer cookie: %w", err)
		}
		return NewOutbound(Config{Version: 3, Gateway: cfg.Gateway, SharedSecret: cfg.SharedSecret, Hostname: cfg.Hostname, MTU: int(cfg.MTU), Static: cfg.Static, LocalAddress: cfg.LocalAddress, LocalSessionID: cfg.LocalSessionID, PeerSessionID: cfg.PeerSessionID, LocalCookie: local, PeerCookie: peer, Sublayer: cfg.Sublayer, RemoteEndID: cfg.RemoteEndID, Address: cfg.Address, Router: cfg.Router, IPv6Address: cfg.IPv6Address, IPv6Router: cfg.IPv6Router, AutoReconnect: cfg.AutoReconnect}, upstream)
	})
}

type tunnelNetwork interface {
	DialContextTCP(context.Context, *net.TCPAddr) (*gonet.TCPConn, error)
	DialUDP(*net.UDPAddr, *net.UDPAddr) (*gonet.UDPConn, error)
	Read([]byte, []tun.ReadPacket) (int, error)
	Write([][]byte, int) (int, error)
	Close() error
}

func NewClient(cfg Config, upstream netapi.Proxy) (*Client, error) {
	return connectClient(context.Background(), cfg, upstream)
}

func connectClient(parent context.Context, cfg Config, upstream netapi.Proxy) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	// Validate credentials before opening the outer transport.
	if err := cfg.validateNetwork(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	transport, err := dialTransport(ctx, cfg, upstream)
	if err != nil {
		return nil, err
	}
	session, err := native.Connect(ctx, cfg.Config, transport)
	if err != nil {
		return nil, err
	}
	info := session.Info()
	var network tunnelNetwork
	if cfg.Version == 2 {
		network, err = wireguard.CreateNetTUN(info.Prefixes, info.MTU)
	} else {
		network, err = newEthernetNetwork(cfg)
	}
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	run, cancelRun := context.WithCancel(context.Background())
	c := &Client{session: session, network: network, ctx: run, cancel: cancelRun, cfg: cfg}
	c.tcp = dialer.NewHappyEyeballsv2Dialer(func(ctx context.Context, ip net.IP, port uint16) (*gonet.TCPConn, error) {
		return network.DialContextTCP(ctx, &net.TCPAddr{IP: ip, Port: int(port)})
	})
	c.wg.Go(c.receive)
	c.wg.Go(c.transmit)
	c.wg.Go(func() { <-session.Done(); c.shutdown() })
	return c, nil
}
func (c *Client) receive() {
	for {
		packet, err := c.session.ReadFrame()
		if err != nil {
			c.shutdown()
			return
		}
		if _, err := c.network.Write([][]byte{packet}, 0); err != nil {
			c.shutdown()
			return
		}
	}
}
func (c *Client) transmit() {
	slab := make([]byte, c.session.Info().MTU+14+2*tun.ReadPacketSpacing)
	packets := make([]tun.ReadPacket, 1)
	for {
		n, err := c.network.Read(slab, packets)
		if err != nil {
			c.shutdown()
			return
		}
		for _, p := range packets[:n] {
			if p.Offset < 0 || p.Size < 1 || p.Offset+p.Size > len(slab) {
				c.shutdown()
				return
			}
			if err := c.session.WriteFrame(slab[p.Offset : p.Offset+p.Size]); err != nil {
				c.shutdown()
				return
			}
		}
	}
}
func (c *Client) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	if err := c.session.Err(); err != nil {
		return nil, err
	}
	conn, err := c.tcp.DialHappyEyeballsv2(ctx, addr)
	if err != nil {
		return nil, err
	}
	return wireguard.NewWrapGoNetTcpConn(conn), nil
}
func (c *Client) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := c.session.Err(); err != nil {
		return nil, err
	}
	var bind *net.UDPAddr
	if ip, ok := addr.(netapi.IPAddress); ok && ip.AddrPort().Addr().Is4() {
		bind = &net.UDPAddr{IP: net.IPv4zero}
	}
	conn, err := c.network.DialUDP(bind, nil)
	if err != nil {
		return nil, err
	}
	return wireguard.NewWrapGoNetUdpConn(context.WithoutCancel(ctx), conn), nil
}
func (c *Client) Ping(context.Context, netapi.Address) (uint64, error) {
	return 0, errors.ErrUnsupported
}
func (c *Client) NodeExtraInfo() contractnode.NodeExtraInfo {
	if c.session.Err() != nil {
		return contractnode.NodeExtraInfo{}
	}
	p := c.session.Info()
	prefixes := make([]string, 0, len(p.Prefixes))
	for _, prefix := range p.Prefixes {
		prefixes = append(prefixes, prefix.String())
	}
	if c.cfg.Version == 3 {
		for _, address := range []string{c.cfg.Address, c.cfg.IPv6Address} {
			if address != "" {
				prefixes = append(prefixes, address)
			}
		}
	}
	info := &contractnode.L2TPInfo{TunnelPrefixes: prefixes, DNS: slices.Clone(p.DNS), Auth: p.Auth, PeerAddress: p.PeerAddress, MTU: int32(p.MTU), LocalTunnelID: p.LocalTunnelID, PeerTunnelID: p.PeerTunnelID, LocalSessionID: p.LocalSessionID, PeerSessionID: p.PeerSessionID}
	if c.cfg.Version == 3 {
		return contractnode.NodeExtraInfo{L2TPv3: info}
	}
	return contractnode.NodeExtraInfo{L2TP: info}
}
func (c *Client) shutdown() {
	c.once.Do(func() { c.cancel(); _ = c.session.Close(); _ = c.network.Close() })
}
func (c *Client) Close() error { c.shutdown(); c.wg.Wait(); return nil }

func dialTransport(ctx context.Context, cfg Config, upstream netapi.Proxy) (net.Conn, error) {
	addr, err := netapi.ParseAddress("udp", cfg.Gateway)
	if err != nil {
		return nil, err
	}
	if upstream == nil || register.IsZero(upstream) {
		upstream = direct.Default
	}
	peer := addr
	if addr.IsFqdn() {
		ips, err := netapi.Bootstrap().LookupIP(ctx, addr.Hostname())
		if err != nil {
			return nil, err
		}
		peer = netapi.ParseIPAddr("udp", ips.Rand(), addr.Port())
	}
	if cfg.LocalAddress != "" {
		store := netapi.WithContext(ctx)
		store.ConnOptions().SetBindAddress(cfg.LocalAddress)
		ctx = store
	}
	socket, err := upstream.PacketConn(ctx, peer)
	if err != nil {
		return nil, err
	}
	if cfg.LocalAddress != "" {
		requested, _ := netip.ParseAddrPort(cfg.LocalAddress)
		actual, err := netapi.ParseSysAddr(socket.LocalAddr())
		if requested.Port() != 0 && (err != nil || actual.Port() != requested.Port()) {
			_ = socket.Close()
			return nil, errors.New("l2tpv3: upstream cannot bind the requested local UDP port")
		}
	}
	return &connectedPacket{PacketConn: socket, peer: peer, pinned: cfg.Static}, nil
}

type connectedPacket struct {
	net.PacketConn
	mu        sync.Mutex
	peer      netapi.Address
	candidate netapi.Address
	pinned    bool
}

func (c *connectedPacket) Read(buf []byte) (int, error) {
	for {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			return n, err
		}
		source, err := netapi.ParseSysAddr(from)
		c.mu.Lock()
		ok := err == nil && source.Hostname() == c.peer.Hostname() && (!c.pinned || source.Port() == c.peer.Port())
		if ok {
			c.candidate = source
		}
		c.mu.Unlock()
		if ok {
			return n, nil
		}
	}
}
func (c *connectedPacket) ConfirmPeer() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.pinned && c.candidate != nil {
		c.peer = c.candidate
		c.pinned = true
	}
}
func (c *connectedPacket) Write(b []byte) (int, error) {
	c.mu.Lock()
	peer := c.peer
	c.mu.Unlock()
	return c.WriteTo(b, peer)
}
func (c *connectedPacket) RemoteAddr() net.Addr { c.mu.Lock(); defer c.mu.Unlock(); return c.peer }

func (c *Config) validateNetwork() error {
	if c.LocalAddress != "" {
		if _, err := netip.ParseAddrPort(c.LocalAddress); err != nil {
			return fmt.Errorf("l2tpv3: local UDP address: %w", err)
		}
	}
	gateway, err := netapi.ParseAddress("udp", c.Gateway)
	if err != nil {
		return err
	}
	if gateway.Hostname() == "" || gateway.Port() == 0 {
		return errors.New("l2tp: gateway requires host and nonzero UDP port")
	}
	if c.Version == 2 {
		return nil
	}
	if c.Address == "" && c.IPv6Address == "" {
		return errors.New("l2tpv3: an IPv4 or IPv6 prefix is required")
	}
	for _, pair := range []struct {
		address, router string
		ipv6            bool
	}{{c.Address, c.Router, false}, {c.IPv6Address, c.IPv6Router, true}} {
		if pair.address == "" {
			if pair.router != "" {
				return errors.New("l2tpv3: router requires an address")
			}
			continue
		}
		prefix, err := netip.ParsePrefix(pair.address)
		if err != nil || prefix.Addr().Is6() != pair.ipv6 || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
			return errors.New("l2tpv3: invalid address prefix")
		}
		if pair.router != "" {
			router, err := netip.ParseAddr(pair.router)
			if err != nil || router.Is6() != pair.ipv6 || router.IsUnspecified() || router.IsMulticast() || router.Zone() != "" {
				return errors.New("l2tpv3: invalid router")
			}
		}
	}
	return nil
}
