// Package amneziawg connects yuhaiin to AmneziaWG v3 peers through the
// upstream proxy and the existing userspace gVisor IP stack.
package amneziawg

import (
	"context"
	"fmt"
	"net"
	"sync"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	awgdevice "github.com/amnezia-vpn/amneziawg-go/v3/device"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

type Client struct {
	netapi.EmptyDispatch
	network *wireguard.NetTun
	engine  *awgdevice.Device
	tcp     *dialer.HappyEyeballsv2Dialer[*gonet.TCPConn]
	once    sync.Once
}

var _ netapi.Proxy = (*Client)(nil)

func init() {
	register.RegisterContractPoint("amneziawg", func(cfg contractnode.AmneziaWG, upstream netapi.Proxy) (netapi.Proxy, error) {
		return NewClient(cfg, upstream)
	})
}

func NewClient(cfg contractnode.AmneziaWG, upstream netapi.Proxy) (*Client, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	ips, err := wireguard.ParseEndpoints(cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("amneziawg: client addresses: %w", err)
	}
	mtu := int(cfg.MTU)
	if mtu == 0 {
		mtu = 1400
	}
	network, err := wireguard.CreateNetTUN(ips, mtu)
	if err != nil {
		return nil, err
	}
	bind := newSocketBind(upstream, cfg.Peers[0].Endpoint)
	engine := awgdevice.NewDevice(newTunAdapter(network), bind, &awgdevice.Logger{
		Verbosef: func(format string, args ...any) { log.Debug(fmt.Sprintf(format, args...)) },
		Errorf:   func(format string, args ...any) { log.Error(fmt.Sprintf(format, args...)) },
	})
	ipc, err := buildIPC(cfg)
	if err != nil {
		engine.Close()
		return nil, err
	}
	if err := engine.IpcSetOperation(ipc); err != nil {
		engine.Close()
		return nil, fmt.Errorf("amneziawg: IPC config: %w", err)
	}
	if err := engine.Up(); err != nil {
		engine.Close()
		return nil, fmt.Errorf("amneziawg: start: %w", err)
	}
	c := &Client{network: network, engine: engine}
	c.tcp = dialer.NewHappyEyeballsv2Dialer(func(ctx context.Context, ip net.IP, port uint16) (*gonet.TCPConn, error) {
		return network.DialContextTCP(ctx, &net.TCPAddr{IP: ip, Port: int(port)})
	})
	return c, nil
}

func (c *Client) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	conn, err := c.tcp.DialHappyEyeballsv2(ctx, addr)
	if err != nil {
		return nil, err
	}
	return wireguard.NewWrapGoNetTcpConn(conn), nil
}

func (c *Client) PacketConn(ctx context.Context, _ netapi.Address) (net.PacketConn, error) {
	conn, err := c.network.DialUDP(nil, nil)
	if err != nil {
		return nil, err
	}
	return wireguard.NewWrapGoNetUdpConn(context.WithoutCancel(ctx), conn), nil
}

func (c *Client) Ping(context.Context, netapi.Address) (uint64, error) {
	return 0, nil
}

func (c *Client) Close() error {
	c.once.Do(func() { c.engine.Close() })
	return nil
}
