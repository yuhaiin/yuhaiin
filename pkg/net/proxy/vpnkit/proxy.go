package vpnkit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/dataplane"
	vpnclient "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/session"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// Client only contains protocol-independent outbound IP packet plumbing.
// Each VPN protocol owns its own registration, credentials and authentication.
type Client struct {
	netapi.EmptyDispatch
	session vpnclient.Session
	bridge  *packetBridge
	network *wireguard.NetTun
	tcp     *dialer.HappyEyeballsv2Dialer[*gonet.TCPConn]
	once    sync.Once
}

var _ netapi.Proxy = (*Client)(nil)

type DialSession func(context.Context, string) (vpnclient.Session, vpnclient.Result, error)

func NewOutbound(name string, dial DialSession) (*Client, error) {
	bridge := newPacketBridge()
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	tunName := "yuhaiin-" + hex.EncodeToString(id[:])
	release, err := dataplane.RegisterVirtualTUN(tunName, bridge)
	if err != nil {
		return nil, err
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	session, assigned, err := dial(ctx, tunName)
	if err != nil {
		_ = bridge.Close()
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if err := assigned.Validate(); err != nil {
		_ = session.Close()
		_ = bridge.Close()
		return nil, fmt.Errorf("%s: invalid assigned tunnel configuration: %w", name, err)
	}
	network, err := bridge.Attach(assigned)
	if err != nil {
		_ = session.Close()
		_ = bridge.Close()
		return nil, err
	}
	c := &Client{session: session, bridge: bridge, network: network}
	c.tcp = dialer.NewHappyEyeballsv2Dialer(func(ctx context.Context, ip net.IP, port uint16) (*gonet.TCPConn, error) {
		return network.DialContextTCP(ctx, &net.TCPAddr{IP: ip, Port: int(port)})
	})
	return c, nil
}
func ParseGateway(s string, defaultPort int) (string, int, error) {
	if s == "" || strings.Contains(s, "://") || strings.ContainsAny(s, "/@?#") {
		return "", 0, errors.New("VPN gateway must be host[:port], without URL scheme")
	}
	if host, port, e := net.SplitHostPort(s); e == nil {
		p, err := strconv.Atoi(port)
		if err != nil || p <= 0 || p > 65535 || host == "" {
			return "", 0, errors.New("invalid VPN gateway port")
		}
		return host, p, nil
	}
	host := strings.Trim(s, "[]")
	if net.ParseIP(host) == nil && strings.Contains(host, ":") {
		return "", 0, errors.New("invalid VPN gateway")
	}
	if host == "" {
		return "", 0, errors.New("empty VPN gateway")
	}
	return host, defaultPort, nil
}
func IsChained(up netapi.Proxy) bool { return up != nil && !register.IsZero(up) }
func EndpointDialer(up netapi.Proxy) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, host string) (net.Conn, error) {
		address, err := netapi.ParseAddress(network, host)
		if err != nil {
			return nil, err
		}
		if IsChained(up) {
			return up.Conn(ctx, address)
		}
		return dialer.DialHappyEyeballsv1(ctx, address)
	}
}
func (c *Client) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	conn, err := c.tcp.DialHappyEyeballsv2(ctx, addr)
	if err != nil {
		return nil, err
	}
	return wireguard.NewWrapGoNetTcpConn(conn), nil
}
func (c *Client) PacketConn(ctx context.Context, _ netapi.Address) (net.PacketConn, error) {
	udp, err := c.network.DialUDP(nil, nil)
	if err != nil {
		return nil, err
	}
	return wireguard.NewWrapGoNetUdpConn(context.WithoutCancel(ctx), udp), nil
}
func (c *Client) Ping(context.Context, netapi.Address) (uint64, error) {
	return 0, errors.ErrUnsupported
}
func (c *Client) Close() error {
	var err error
	c.once.Do(func() { err = c.session.Close(); _ = c.bridge.Close() })
	return err
}
