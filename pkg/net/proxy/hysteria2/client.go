package hysteria2

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	ytls "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tls"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	hyclient "github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/extras/v2/obfs"
	"github.com/apernet/hysteria/extras/v2/transport/udphop"
)

func init() {
	register.RegisterContractPoint("hysteria2", NewClient)
}

// Client shares one QUIC connection, with independent TCP streams and UDP sessions.
// Gecko and HTTP masquerade configuration are deferred; they are
// intentionally absent from the public contract until their lifecycle is supported.
type Client struct {
	netapi.EmptyDispatch
	config    contractnode.Hysteria2
	parent    netapi.Proxy
	ctx       context.Context
	cancel    context.CancelFunc
	gate      chan struct{}
	session   *clientSession
	closeOnce sync.Once
	closeErr  error
}

func validateOptions(auth, salamander string, up, down uint64) error {
	if auth == "" {
		return errors.New("hysteria2 auth must not be empty")
	}
	if salamander != "" && len(salamander) < 4 {
		return errors.New("hysteria2 Salamander password must be at least 4 bytes")
	}
	for _, v := range []uint64{up, down} {
		if v != 0 && v < 65536 {
			return errors.New("hysteria2 bandwidth must be zero or at least 65536 bytes/second")
		}
	}
	return nil
}

func NewClient(config contractnode.Hysteria2, parent netapi.Proxy) (netapi.Proxy, error) {
	if err := validateOptions(config.Auth, config.SalamanderPassword, config.UploadBPS, config.DownloadBPS); err != nil {
		return nil, err
	}
	if config.Host == "" {
		return nil, errors.New("hysteria2 server host is empty")
	}
	if err := validateHopAddresses(config); err != nil {
		return nil, err
	}
	if _, err := hopIntervalConfig(config); err != nil {
		return nil, err
	}
	if register.IsZero(parent) {
		parent = nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{config: config, parent: parent, ctx: ctx, cancel: cancel, gate: make(chan struct{}, 1)}, nil
}

func (c *Client) getSession(ctx context.Context) (*clientSession, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, net.ErrClosed
	case c.gate <- struct{}{}:
	}
	defer func() { <-c.gate }()
	if c.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if c.session != nil && c.session.Context().Err() == nil {
		return c.session, nil
	}
	if c.session != nil {
		_ = c.session.Close()
		c.session = nil
	}
	setup, cancel := context.WithTimeout(ctx, configuration.Timeout)
	defer cancel()
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	server, ports, err := parseServerAddress(c.config.Host)
	if err != nil {
		return nil, err
	}
	cfg := c.config.TLS
	tlsConfig := ytls.ParseTLSConfig(ytls.TLSConfig{Enable: true, ServerNames: cfg.ServerNames, CACert: cfg.CACert, InsecureSkipVerify: cfg.InsecureSkipVerify, ECHConfig: cfg.ECHConfig})
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = server.Hostname()
	}
	var serverAddr net.Addr
	if len(c.config.HopAddresses) != 0 {
		serverAddr, err = resolveAddressHops(setup, c.config)
		if err != nil {
			return nil, err
		}
	} else {
		remote, err := resolveHopAddress(setup, server)
		if err != nil {
			return nil, err
		}
		serverAddr = remote
		if ports != nil {
			if remote.Zone != "" {
				return nil, errors.New("hysteria2 port hopping does not support scoped IPv6 addresses")
			}
			_, portStr, _ := net.SplitHostPort(c.config.Host)
			serverAddr = &udphop.UDPHopAddr{IP: remote.IP, Ports: ports.Ports(), PortStr: portStr}
		}
	}
	interval, err := hopIntervalConfig(c.config)
	if err != nil {
		return nil, err
	}
	factory := &connFactory{ctx: setup, hopCtx: c.ctx, parent: c.parent, password: c.config.SalamanderPassword, hopInterval: interval}
	session, _, err := hyclient.NewClientContext(setup, &hyclient.Config{
		ConnFactory: factory,
		ServerAddr:  serverAddr, Auth: c.config.Auth,
		TLSConfig:       hyclient.TLSConfig{ServerName: tlsConfig.ServerName, RootCAs: tlsConfig.RootCAs, InsecureSkipVerify: tlsConfig.InsecureSkipVerify, ECHConfigList: tlsConfig.EncryptedClientHelloConfigList},
		BandwidthConfig: hyclient.BandwidthConfig{MaxTx: c.config.UploadBPS, MaxRx: c.config.DownloadBPS},
	})
	if err != nil {
		return nil, fmt.Errorf("hysteria2 connect: %w", err)
	}
	if c.ctx.Err() != nil {
		_ = session.Close()
		return nil, net.ErrClosed
	}
	c.session = &clientSession{ContextClient: session, local: factory.local}
	return c.session, nil
}

func (c *Client) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	session, err := c.getSession(ctx)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, configuration.Timeout)
	defer cancel()
	return session.TCPContext(ctx, addr.String())
}

func (c *Client) PacketConn(ctx context.Context, _ netapi.Address) (net.PacketConn, error) {
	session, err := c.getSession(ctx)
	if err != nil {
		return nil, err
	}
	udp, err := session.UDP()
	if err != nil {
		return nil, err
	}
	return newPacketConn(udp, session.local), nil
}

func (c *Client) Ping(context.Context, netapi.Address) (uint64, error) {
	return 0, errors.ErrUnsupported
}

func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		c.gate <- struct{}{}
		defer func() { <-c.gate }()
		if c.session != nil {
			c.closeErr = c.session.Close()
		}
		if c.parent != nil {
			c.closeErr = errors.Join(c.closeErr, c.parent.Close())
		}
	})
	return c.closeErr
}

type clientSession struct {
	hyclient.ContextClient
	local net.Addr
}

type connFactory struct {
	local       net.Addr
	ctx         context.Context
	parent      netapi.Proxy
	password    string
	hopCtx      context.Context
	hopInterval udphop.HopIntervalConfig
}

func (f *connFactory) New(remote net.Addr) (net.PacketConn, error) {
	var conn net.PacketConn
	var err error
	if hop, ok := remote.(*addressHopAddr); ok {
		conn, err = newAddressHopPacketConn(f.ctx, f.hopCtx, hop, f.hopInterval, f.listenPacket)
	} else if hop, ok := remote.(*udphop.UDPHopAddr); ok {
		// The setup context ends after authentication. Subsequent sockets must
		// use the client's lifetime context so hopping can continue afterwards.
		initial := true
		conn, err = udphop.NewUDPHopPacketConn(hop, f.hopInterval, func() (net.PacketConn, error) {
			ctx := f.hopCtx
			if initial {
				ctx, initial = f.ctx, false
			}
			ctx, cancel := context.WithTimeout(ctx, configuration.Timeout)
			defer cancel()
			return f.listenPacket(ctx, &net.UDPAddr{IP: hop.IP, Port: int(hop.Ports[0])})
		})
		if err == nil && f.parent != nil {
			// Proxy packet connections need not expose a UDP file descriptor.
			// Hide udphop's unconditional SyscallConn method on this path so QUIC
			// uses PacketConn rather than failing on an unsupported syscall.
			conn = packetConnOnly{conn}
		}
	} else {
		conn, err = f.listenPacket(f.ctx, remote)
	}
	if err != nil {
		return nil, err
	}
	f.local = conn.LocalAddr()
	if f.password != "" {
		wrapped, err := obfs.WrapPacketConnSalamander(conn, []byte(f.password))
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		conn = wrapped
	}
	return conn, nil
}

type packetConnOnly struct{ net.PacketConn }

func (f *connFactory) listenPacket(ctx context.Context, remote net.Addr) (net.PacketConn, error) {
	var conn net.PacketConn
	var err error
	if f.parent == nil {
		network := "udp"
		if udp, ok := remote.(*net.UDPAddr); ok {
			// Select the family explicitly instead of relying on a dual-stack
			// wildcard socket, including when hopping between IPv4 and IPv6.
			network = "udp6"
			if udp.IP.To4() != nil {
				network = "udp4"
			}
		}
		conn, err = dialer.ListenPacket(ctx, network, "", func(o *dialer.Options) {
			if udp, ok := remote.(*net.UDPAddr); ok {
				o.PacketConnHintAddress = udp
			}
		})
	} else {
		addr, e := netapi.ParseSysAddr(remote)
		if e != nil {
			return nil, e
		}
		conn, err = f.parent.PacketConn(ctx, addr)
	}
	if err != nil {
		return nil, err
	}
	return conn, nil
}
