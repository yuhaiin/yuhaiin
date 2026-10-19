//go:build (((linux && !android) || darwin) && (amd64 || arm64)) || (windows && amd64) || (android && arm64 && cgo)

// Package zerotier provides a device-free ZeroTier outbound using the official
// ZeroTierOne core and yuhaiin's lightweight TCP/IP stack.
package zerotier

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	zt "github.com/yuhaiin/zerotier-go"
)

const defaultListen = ":0"

var identities sync.Map
var safeIdentity = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

type session struct {
	tun      *wireguard.LightweightNetTun
	bridge   *etherBridge
	mtu      int
	prefixes []netip.Prefix
	mac      uint64
}

// Client owns a single ZeroTier identity, a physical UDP socket, and a
// dynamically configured in-memory IP stack. It never creates a system NIC.
type Client struct {
	netapi.EmptyDispatch
	node      *zt.UDPNode
	id        zt.NetworkID
	state     string
	closing   chan struct{}
	ready     chan struct{}
	once      sync.Once
	readyOnce sync.Once
	wg        sync.WaitGroup
	configs   chan zt.NetworkConfig
	frames    chan zt.Frame
	mu        sync.RWMutex
	active    *session
	failure   error
}

var _ netapi.Proxy = (*Client)(nil)

func init() {
	register.RegisterContractPoint("zerotier", func(c contractnode.ZeroTier, previous netapi.Proxy) (netapi.Proxy, error) {
		return NewClient(c, previous)
	})
}

// NewClient starts the ZeroTier protocol engine without waiting for network
// approval. Dialers wait until the controller supplies managed addresses.
func NewClient(cfg contractnode.ZeroTier, previous netapi.Proxy) (*Client, error) {
	if !register.IsZero(previous) {
		return nil, errors.New("zerotier: native physical UDP currently requires a root outbound; chaining is unsupported")
	}
	id, err := zt.ParseNetworkID(cfg.NetworkID)
	if err != nil {
		return nil, err
	}
	name := cfg.Identity
	if name == "" {
		name = id.String()
	}
	if !safeIdentity.MatchString(name) {
		return nil, errors.New("zerotier: identity must be 1-64 ASCII letters, digits, underscores or hyphens")
	}
	dir := filepath.Join(configuration.DataDir.Load(), "zerotier", name)
	dir, err = filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if _, busy := identities.LoadOrStore(dir, struct{}{}); busy {
		return nil, fmt.Errorf("zerotier: identity %q is already active; give this node a distinct identity", name)
	}
	store, err := zt.NewFileStore(dir)
	if err != nil {
		identities.Delete(dir)
		return nil, fmt.Errorf("zerotier: open identity store: %w", err)
	}
	c := &Client{
		id: id, state: dir, closing: make(chan struct{}), ready: make(chan struct{}),
		configs: make(chan zt.NetworkConfig, 8), frames: make(chan zt.Frame, 512),
	}
	addr := cfg.Listen
	if addr == "" {
		addr = defaultListen
	}
	c.node, err = zt.ListenUDP(zt.Config{
		Store: store, LibraryPath: cfg.LibraryPath,
		LowBandwidth:    cfg.LowBandwidth,
		OnFrame:         c.onFrame,
		OnNetworkConfig: c.onNetworkConfig,
	}, "udp", addr)
	if err != nil {
		identities.Delete(dir)
		return nil, fmt.Errorf("zerotier: start core: %w", err)
	}
	c.wg.Add(2)
	go c.configLoop()
	go c.sendLoop()
	if err := c.node.Node.Join(id); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("zerotier: join network: %w", err)
	}
	for _, moon := range cfg.Moons {
		moonID, parseErr := strconv.ParseUint(strings.TrimPrefix(moon.ID, "0x"), 16, 64)
		seed, seedErr := strconv.ParseUint(strings.TrimPrefix(moon.Seed, "0x"), 16, 64)
		if parseErr != nil || seedErr != nil || moonID == 0 || seed == 0 {
			_ = c.Close()
			return nil, fmt.Errorf("zerotier: invalid moon ID or seed: %q %q", moon.ID, moon.Seed)
		}
		if err := c.node.Node.Orbit(moonID, seed); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("zerotier: orbit moon: %w", err)
		}
	}
	return c, nil
}

func (c *Client) onNetworkConfig(cfg zt.NetworkConfig) {
	if cfg.ID != c.id {
		return
	}
	// Do not invoke native Node methods synchronously in a callback.
	select {
	case c.configs <- cfg:
	default:
		// Prefer the latest snapshot if a burst fills the queue.
		select {
		case <-c.configs:
		default:
		}
		select {
		case c.configs <- cfg:
		default:
		}
	}
}

func (c *Client) configLoop() {
	defer c.wg.Done()
	for {
		select {
		case <-c.closing:
			return
		case cfg := <-c.configs:
			c.applyConfig(cfg)
		}
	}
}

func (c *Client) applyConfig(cfg zt.NetworkConfig) {
	if cfg.Operation == zt.NetworkDown || cfg.Operation == zt.NetworkDestroyed {
		c.deactivate(errors.New("zerotier: network disconnected"))
		return
	}
	if cfg.Status != zt.NetworkOK {
		switch cfg.Status {
		case zt.NetworkAccessDenied, zt.NetworkNotFound, zt.NetworkPortError,
			zt.NetworkAuthenticationRequired, zt.NetworkClientTooOld:
			c.deactivate(fmt.Errorf("zerotier: network controller status %d", cfg.Status))
			c.readyOnce.Do(func() { close(c.ready) })
		}
		return
	}
	if len(cfg.Addresses) == 0 || cfg.MAC == 0 {
		return
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = zt.DefaultMTU
	}
	if mtu < 576 || mtu > 65535 {
		c.deactivate(fmt.Errorf("zerotier: invalid controller MTU %d", mtu))
		c.readyOnce.Do(func() { close(c.ready) })
		return
	}
	c.mu.RLock()
	old := c.active
	unchanged := old != nil && old.mtu == mtu && old.mac == cfg.MAC && slices.Equal(old.prefixes, cfg.Addresses)
	c.mu.RUnlock()
	if unchanged {
		old.bridge.updateRoutes(cfg.Routes)
		return
	}
	tun, err := wireguard.CreateLightweightNetTUN(cfg.Addresses, mtu)
	if err != nil {
		c.deactivate(fmt.Errorf("zerotier: initialize lightweight stack: %w", err))
		c.readyOnce.Do(func() { close(c.ready) })
		return
	}
	bridge := newEtherBridge(cfg, func(f zt.Frame) {
		select {
		case c.frames <- f:
		case <-c.closing:
		default: // Native callbacks must never wait on a full output queue.
		}
	}, tun.InjectPacket)
	s := &session{tun: tun, bridge: bridge, mtu: mtu, mac: cfg.MAC, prefixes: append([]netip.Prefix(nil), cfg.Addresses...)}
	c.mu.Lock()
	old = c.active
	c.active = s
	c.failure = nil
	c.mu.Unlock()
	c.readyOnce.Do(func() { close(c.ready) })
	if old != nil {
		_ = old.tun.Close()
	}
	c.wg.Add(1)
	go c.packetLoop(s)
	// Subscribe from this goroutine, never the native callback dispatcher.
	_ = c.node.Node.Subscribe(c.id, 0xffffffffffff, 0)
	for _, addr := range cfg.Addresses {
		if addr.Addr().Is6() {
			group := solicitedMAC(addr.Addr())
			_ = c.node.Node.Subscribe(c.id, group, 0)
		}
	}
}

func (c *Client) deactivate(err error) {
	c.mu.Lock()
	old := c.active
	c.active = nil
	c.failure = err
	c.mu.Unlock()
	if old != nil {
		_ = old.tun.Close()
	}
}

func (c *Client) packetLoop(s *session) {
	defer c.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, err := s.tun.ReadPacket(buf)
		if err != nil {
			return
		}
		s.bridge.outgoing(buf[:n])
	}
}

func (c *Client) sendLoop() {
	defer c.wg.Done()
	for {
		select {
		case <-c.closing:
			return
		case frame := <-c.frames:
			if err := c.node.Node.ProcessFrame(frame); err != nil && errors.Is(err, zt.ErrClosed) {
				return
			}
		}
	}
}

func (c *Client) onFrame(frame zt.Frame) {
	if frame.NetworkID != c.id {
		return
	}
	c.mu.RLock()
	s := c.active
	c.mu.RUnlock()
	if s != nil {
		s.bridge.incoming(frame)
	}
}

func (c *Client) current(ctx context.Context) (*wireguard.LightweightNetTun, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closing:
		return nil, zt.ErrClosed
	case <-c.ready:
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.active == nil {
		if c.failure != nil {
			return nil, c.failure
		}
		return nil, errors.New("zerotier: network has no usable managed addresses")
	}
	return c.active.tun, nil
}

func (c *Client) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	tun, err := c.current(ctx)
	if err != nil {
		return nil, err
	}
	d := dialer.NewHappyEyeballsv2Dialer(func(ctx context.Context, ip net.IP, port uint16) (net.Conn, error) {
		return tun.DialContextTCP(ctx, &net.TCPAddr{IP: ip, Port: int(port)})
	})
	return d.DialHappyEyeballsv2(ctx, addr)
}

func (c *Client) PacketConn(ctx context.Context, _ netapi.Address) (net.PacketConn, error) {
	tun, err := c.current(ctx)
	if err != nil {
		return nil, err
	}
	pc, err := tun.DialUDP(nil, nil)
	if err != nil {
		return nil, err
	}
	return wireguard.NewWrapGoNetUdpConn(context.WithoutCancel(ctx), pc), nil
}

func (c *Client) Ping(context.Context, netapi.Address) (uint64, error) {
	return 0, errors.New("zerotier: ICMP ping is not implemented")
}

func (c *Client) Close() error {
	var result error
	c.once.Do(func() {
		close(c.closing)
		c.deactivate(zt.ErrClosed)
		if c.node != nil {
			result = c.node.Close()
		}
		c.wg.Wait()
		identities.Delete(c.state)
	})
	return result
}
