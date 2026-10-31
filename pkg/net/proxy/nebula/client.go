// Package nebula runs the upstream Nebula protocol in process, delivering
// decrypted IP packets to yuhaiin's lightweight userspace TCP/IP stack.
package nebula

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	upstreamnebula "github.com/slackhq/nebula"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay"
	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/routing"
)

const defaultMTU = 1300

// Client owns one Nebula control instance and its entirely in-memory IP stack.
// Nebula's UDP underlay is supplied by upstream, not the preceding Proxy.
type Client struct {
	netapi.EmptyDispatch
	control *upstreamnebula.Control
	network *wireguard.LightweightNetTun
	tcp     *dialer.HappyEyeballsv2Dialer[net.Conn]
	once    sync.Once
}

var _ netapi.Proxy = (*Client)(nil)
var _ overlay.Device = (*memoryDevice)(nil)

func init() {
	register.RegisterContractPoint("nebula", func(c contractnode.Nebula, previous netapi.Proxy) (netapi.Proxy, error) {
		return NewClient(c, previous)
	})
}

// NewClient accepts standard Nebula YAML, using embedded certificates. It
// rejects a preexisting upstream instead of silently bypassing that upstream.
func NewClient(cfg contractnode.Nebula, previous netapi.Proxy) (*Client, error) {
	if !register.IsZero(previous) {
		return nil, errors.New("nebula: chained upstream proxies are not supported by the native UDP underlay")
	}
	logger := slog.Default().With("component", "nebula")
	c, err := parseConfig(cfg.ConfigYAML, logger)
	if err != nil {
		return nil, err
	}
	var network *wireguard.LightweightNetTun
	factory := func(_ *config.C, _ *slog.Logger, networks []netip.Prefix, _ int) (overlay.Device, error) {
		if len(networks) == 0 {
			return nil, errors.New("nebula: the certificate contains no overlay networks")
		}
		network, err = wireguard.CreateLightweightNetTUN(networks, c.GetInt("tun.mtu", defaultMTU))
		if err != nil {
			return nil, fmt.Errorf("nebula: create in-memory IP stack: %w", err)
		}
		return &memoryDevice{network: network, networks: networks}, nil
	}
	control, err := upstreamnebula.Main(c, false, "", logger, factory)
	if err != nil {
		return nil, fmt.Errorf("nebula: initialize: %w", err)
	}
	if err := control.Start(); err != nil {
		control.Stop()
		return nil, fmt.Errorf("nebula: start: %w", err)
	}
	if network == nil {
		control.Stop()
		return nil, errors.New("nebula: device factory was not called")
	}
	client := &Client{control: control, network: network}
	client.tcp = dialer.NewHappyEyeballsv2Dialer(func(ctx context.Context, ip net.IP, port uint16) (net.Conn, error) {
		return network.DialContextTCP(ctx, &net.TCPAddr{IP: ip, Port: int(port)})
	})
	return client, nil
}

// parseConfig is intentionally restrictive about features that create host
// resources or bypass the in-memory packet interface.
func parseConfig(raw string, logger *slog.Logger) (*config.C, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("nebula: config_yaml is required")
	}
	c := config.NewC(logger)
	if err := c.LoadString(raw); err != nil {
		return nil, fmt.Errorf("nebula: parse configuration: %w", err)
	}
	if c.GetBool("tun.disabled", false) || c.GetBool("tun.use_system_route_table", false) {
		return nil, errors.New("nebula: disabled TUN and system route table are unsupported in userspace mode")
	}
	if c.IsSet("tun.routes") || c.IsSet("tun.unsafe_routes") {
		return nil, errors.New("nebula: custom tun.routes/unsafe_routes require gateway routing support and are not yet supported")
	}
	if c.GetBool("sshd.enabled", false) || c.GetBool("lighthouse.serve_dns", false) {
		return nil, errors.New("nebula: SSH server and Lighthouse DNS responder must be disabled")
	}
	if c.GetString("stats.type", "none") != "none" {
		return nil, errors.New("nebula: external stats listeners are disabled")
	}
	routines := c.GetInt("routines", 0)
	if routines != 0 {
		if routines < 1 {
			routines = 1
		}
	} else {
		routines = max(c.GetInt("tun.routines", 1), c.GetInt("listen.routines", 1))
	}
	if routines != 1 {
		return nil, errors.New("nebula: multiple packet routines are not supported by the in-memory device")
	}
	mtu := c.GetInt("tun.mtu", defaultMTU)
	if mtu < 576 || mtu > 9000 {
		return nil, fmt.Errorf("nebula: invalid MTU %d", mtu)
	}
	return c, nil
}

func (c *Client) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	return c.tcp.DialHappyEyeballsv2(ctx, addr)
}

func (c *Client) PacketConn(ctx context.Context, _ netapi.Address) (net.PacketConn, error) {
	conn, err := c.network.DialUDP(nil, nil)
	if err != nil {
		return nil, err
	}
	return wireguard.NewWrapGoNetUdpConn(context.WithoutCancel(ctx), conn), nil
}

func (c *Client) Ping(context.Context, netapi.Address) (uint64, error) {
	return 0, errors.New("nebula: ICMP ping is not implemented")
}

func (c *Client) Close() error {
	c.once.Do(func() { c.control.Stop() })
	return nil
}

// memoryDevice implements the official Nebula overlay.Device without a host
// TUN, operating-system route changes, or elevated privileges.
type memoryDevice struct {
	network  *wireguard.LightweightNetTun
	networks []netip.Prefix
}

func (m *memoryDevice) Read(p []byte) (int, error) {
	return m.network.ReadPacket(p)
}
func (m *memoryDevice) Write(p []byte) (int, error) {
	if err := m.network.InjectPacket(p); err != nil {
		return 0, err
	}
	return len(p), nil
}
func (m *memoryDevice) Close() error                          { return m.network.Close() }
func (m *memoryDevice) Activate() error                       { return nil }
func (m *memoryDevice) Networks() []netip.Prefix              { return m.networks }
func (m *memoryDevice) Name() string                          { return "yuhaiin-nebula" }
func (m *memoryDevice) RoutesFor(netip.Addr) routing.Gateways { return routing.Gateways{} }
func (m *memoryDevice) Queues(int) ([]tio.Queue, error) {
	// The lightweight stack has one packet reader. Match Nebula's single-queue
	// backends and reserve enough scratch space for any IP datagram.
	return []tio.Queue{tio.NewSingleQueue(m, 65535)}, nil
}
