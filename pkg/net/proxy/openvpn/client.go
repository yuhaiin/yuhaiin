// Package openvpn exposes a native userspace OpenVPN tunnel as a yuhaiin outbound.
package openvpn

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/openvpn/native"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

type Config struct {
	native.Config
	AutoReconnect bool
}

type Client struct {
	netapi.EmptyDispatch
	session *native.Session
	network *wireguard.NetTun
	tcp     *dialer.HappyEyeballsv2Dialer[*gonet.TCPConn]
	once    sync.Once
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

var _ netapi.Proxy = (*Client)(nil)

func init() {
	register.RegisterContractPoint("openvpn", func(cfg contractnode.OpenVPN, upstream netapi.Proxy) (netapi.Proxy, error) {
		direction := -1
		if cfg.KeyDirection != nil {
			direction = int(*cfg.KeyDirection)
		}
		return NewOutbound(Config{
			Gateway: cfg.Gateway, Network: cfg.Network, CACertPEM: cfg.CACertPEM,
			ClientCertPEM: cfg.ClientCertPEM, ClientKeyPEM: cfg.ClientKeyPEM,
			ServerName: cfg.ServerName, Username: cfg.Username, Password: cfg.Password,
			TLSAuthKey: cfg.TLSAuthKey, TLSCryptKey: cfg.TLSCryptKey, KeyDirection: direction,
			Auth: cfg.Auth, DataCiphers: slices.Clone(cfg.DataCiphers), MTU: int(cfg.MTU),
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			RenegotiateAfter:   time.Duration(cfg.RenegotiateSeconds) * time.Second, AutoReconnect: cfg.AutoReconnect}, upstream)
	})
}

func NewClient(cfg Config, upstream netapi.Proxy) (*Client, error) {
	return connectClient(context.Background(), cfg, upstream)
}

func connectClient(parent context.Context, cfg Config, upstream netapi.Proxy) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	// Validate credentials before opening the outer transport.
	if _, err := cfg.TLSConfig(); err != nil {
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
	network, err := wireguard.CreateNetTUN(info.Prefixes, info.MTU)
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	run, cancelRun := context.WithCancel(context.Background())
	c := &Client{session: session, network: network, ctx: run, cancel: cancelRun}
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
		packet, err := c.session.ReadIP()
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
	slab := make([]byte, c.session.Info().MTU+2*tun.ReadPacketSpacing)
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
			if err := c.session.WriteIP(slab[p.Offset : p.Offset+p.Size]); err != nil {
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
	return contractnode.NodeExtraInfo{OpenVPN: &contractnode.OpenVPNInfo{
		TunnelPrefixes: prefixes, DNS: slices.Clone(p.DNS), Routes: slices.Clone(p.Routes),
		Gateway: p.Gateway, Cipher: p.Cipher, MTU: int32(p.MTU),
	}}
}
func (c *Client) shutdown() {
	c.once.Do(func() { c.cancel(); _ = c.session.Close(); _ = c.network.Close() })
}
func (c *Client) Close() error { c.shutdown(); c.wg.Wait(); return nil }

func dialTransport(ctx context.Context, cfg Config, upstream netapi.Proxy) (*native.Transport, error) {
	addr, err := netapi.ParseAddress(cfg.Network, cfg.Gateway)
	if err != nil {
		return nil, err
	}
	if upstream == nil || register.IsZero(upstream) {
		upstream = direct.Default
	}
	if cfg.Network == "tcp" {
		conn, err := upstream.Conn(ctx, addr)
		if err != nil {
			return nil, err
		}
		return &native.Transport{Conn: conn, TCP: true}, nil
	}
	// Resolve once to pin the expected peer for both writes and receives. Never
	// silently open an unproxied socket when a chained proxy cannot carry UDP.
	peer := addr
	if addr.IsFqdn() {
		ips, err := netapi.Bootstrap().LookupIP(ctx, addr.Hostname())
		if err != nil {
			return nil, err
		}
		peer = netapi.ParseIPAddr("udp", ips.Rand(), addr.Port())
	}
	socket, err := upstream.PacketConn(ctx, peer)
	if err != nil {
		return nil, err
	}
	return &native.Transport{Conn: &connectedPacket{PacketConn: socket, peer: peer}}, nil
}

type connectedPacket struct {
	net.PacketConn
	peer netapi.Address
}

func (c *connectedPacket) Read(buf []byte) (int, error) {
	for {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			return n, err
		}
		source, err := netapi.ParseSysAddr(from)
		if err == nil && source.Hostname() == c.peer.Hostname() && source.Port() == c.peer.Port() {
			return n, nil
		}
	}
}
func (c *connectedPacket) Write(buf []byte) (int, error) { return c.WriteTo(buf, c.peer) }
func (c *connectedPacket) RemoteAddr() net.Addr          { return c.peer }
