package globalprotect

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

type Client struct {
	netapi.EmptyDispatch
	control      *control
	session      session
	tunnel       *wireguard.NetTun
	conn         *tls.Conn
	esp          *espTunnel
	ctx          context.Context
	cancel       context.CancelFunc
	closeOnce    sync.Once
	writeMu      sync.Mutex
	connMu       sync.RWMutex
	rekeyWait    chan struct{}
	lastActivity atomic.Int64
	lastDPD      atomic.Int64
	closed       atomic.Bool
	mu           sync.Mutex
	failure      error
	done         chan struct{}
	dialer       *dialer.HappyEyeballsv2Dialer[*gonet.TCPConn]
	mtu          int
	tunnelURL    string
	extraInfo    contractnode.GlobalProtectInfo
}

const (
	globalprotectDPDInterval = 10 * time.Second
	globalprotectDPDTimeout  = 3 * globalprotectDPDInterval
)

var (
	errGatewayIdleDisconnect = errors.New("globalprotect: gateway disconnect-on-idle timeout elapsed")
	errDPDTimeout            = errors.New("globalprotect: gateway DPD response timed out")
)

var _ netapi.Proxy = (*Client)(nil)

func init() {
	register.RegisterContractPoint("globalprotect", func(config contractnode.GlobalProtect, p netapi.Proxy) (netapi.Proxy, error) {
		return NewClient(Config{
			Gateway: config.Gateway, Username: config.Username, Password: config.Password,
			Computer: config.Computer, CACertPEM: config.CACertPEM,
			InsecureSkipVerify: config.InsecureSkipVerify, MTU: int(config.MTU), UseESP: config.UseESP,
		}, p)
	})
}

// connectClient establishes one session with a directly addressed gateway.
func connectClient(parent context.Context, config Config) (_ *Client, err error) {
	if config.Username == "" || config.Password == "" {
		return nil, errors.New("globalprotect: username and password required")
	}
	control, err := newControl(config)
	if err != nil {
		return nil, err
	}
	defer control.close()
	ctx, cancel := context.WithTimeout(parent, 25*time.Second)
	defer cancel()

	if err := control.prelogin(ctx); err != nil {
		return nil, err
	}
	s, err := control.login(ctx, config.Username, config.Password)
	if err != nil {
		return nil, err
	}
	loginTime := time.Now()
	success := false
	defer func() {
		if !success {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cleanupCancel()
			_ = control.logout(cleanupCtx, s)
		}
	}()
	cfg, addr, err := control.getConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	authLifetime := secondsDuration(cfg.Lifetime)
	if authLifetime > 0 && time.Since(loginTime) >= authLifetime {
		return nil, errors.New("globalprotect: authentication lifetime elapsed during setup")
	}

	var esp *espTunnel
	if config.UseESP && cfg.IPSec != nil {
		esp, err = connectESP(ctx, control, cfg, addr.Addr())
		if err != nil {
			log.Debug("globalprotect: ESP unavailable, trying SSL tunnel", "error", err)
		}
	}
	var conn *tls.Conn
	if esp == nil {
		conn, err = connectTunnel(ctx, control, s, cfg.TunnelURL)
		if err != nil {
			return nil, err
		}
	}
	closeTransport := func() {
		if esp != nil {
			_ = esp.socket.Close()
		}
		if conn != nil {
			_ = conn.Close()
		}
	}

	mtuValue := config.MTU
	if mtuValue == 0 {
		mtuValue = cfg.MTU
	}
	mtu := mtuValue
	if esp != nil {
		if mtu == 0 {
			mtu = 1400
		}
	} else {
		mtu = calculateMTU(conn, mtuValue)
	}
	if mtuValue == 0 && mtu > 1500 {
		mtu = 1500
	}
	if mtu < 576 || mtu > 1500 {
		closeTransport()
		return nil, fmt.Errorf("globalprotect: invalid MTU %d", mtu)
	}
	network, err := wireguard.CreateNetTUN([]netip.Prefix{addr}, mtu)
	if err != nil {
		closeTransport()
		return nil, err
	}
	if err := parent.Err(); err != nil {
		_ = network.Close()
		closeTransport()
		return nil, err
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	client := &Client{
		control: control, session: s, tunnel: network, conn: conn,
		ctx: runCtx, cancel: runCancel, done: make(chan struct{}), mtu: mtu,
		tunnelURL: cfg.TunnelURL, esp: esp,
		extraInfo: contractnode.GlobalProtectInfo{
			TunnelPrefix:                 addr.String(),
			AccessRoutesIPv4:             slices.Clone(cfg.AccessRoutes),
			ExcludeRoutesIPv4:            slices.Clone(cfg.ExcludeRoutes),
			AccessRoutesIPv6:             slices.Clone(cfg.AccessRoutesV6),
			ExcludeRoutesIPv6:            slices.Clone(cfg.ExcludeRoutesV6),
			DNS:                          slices.Clone(cfg.DNS),
			DNSv6:                        slices.Clone(cfg.DNSv6),
			DNSSuffix:                    slices.Clone(cfg.DNSSuffix),
			NoDirectAccessToLocalNetwork: cfg.NoDirectAccess,
		},
		dialer: dialer.NewHappyEyeballsv2Dialer(func(ctx context.Context, ip net.IP, port uint16) (*gonet.TCPConn, error) {
			return network.DialContextTCP(ctx, &net.TCPAddr{IP: ip, Port: int(port)})
		}),
	}
	client.lastActivity.Store(time.Now().UnixNano())
	client.lastDPD.Store(time.Now().UnixNano())
	if len(cfg.DNS) > 0 || len(cfg.DNSv6) > 0 || len(cfg.DNSSuffix) > 0 ||
		len(cfg.AccessRoutes) > 0 || len(cfg.ExcludeRoutes) > 0 ||
		len(cfg.AccessRoutesV6) > 0 || len(cfg.ExcludeRoutesV6) > 0 || strings.TrimSpace(cfg.NoDirectAccess) != "" {
		log.Warn("globalprotect gateway DNS, routes, and local-network policy are not applied automatically",
			"dns_count", len(cfg.DNS)+len(cfg.DNSv6), "dns_suffix_count", len(cfg.DNSSuffix),
			"route_count", len(cfg.AccessRoutes)+len(cfg.ExcludeRoutes)+len(cfg.AccessRoutesV6)+len(cfg.ExcludeRoutesV6),
			"local_network_policy", strings.TrimSpace(cfg.NoDirectAccess) != "")
	}
	if esp != nil {
		client.extraInfo.DataTransport = "esp"
	} else {
		client.extraInfo.DataTransport = "ssl"
	}
	success = true
	go client.sendPackets()
	if esp != nil {
		go client.receiveESP()
	} else {
		go client.receivePackets()
	}
	go client.keepalive()
	if cfg.Timeout > 0 {
		if esp != nil {
			go client.expireSessionAfter(secondsDuration(cfg.Timeout) / 2)
		} else {
			go client.rekeyAfter(secondsDuration(cfg.Timeout))
		}
	}
	if cfg.Lifetime > 0 {
		go client.expireSessionAfter(authLifetime - time.Since(loginTime))
	}
	if cfg.DisconnectOnIdle > 0 {
		go client.expireIdleAfter(secondsDuration(cfg.DisconnectOnIdle))
	}
	return client, nil
}

// NodeExtraInfo returns a copy of the configuration received during this
// client's getconfig request.
func (c *Client) NodeExtraInfo() contractnode.NodeExtraInfo {
	info := c.extraInfo
	info.AccessRoutesIPv4 = slices.Clone(info.AccessRoutesIPv4)
	info.ExcludeRoutesIPv4 = slices.Clone(info.ExcludeRoutesIPv4)
	info.AccessRoutesIPv6 = slices.Clone(info.AccessRoutesIPv6)
	info.ExcludeRoutesIPv6 = slices.Clone(info.ExcludeRoutesIPv6)
	info.DNS = slices.Clone(info.DNS)
	info.DNSv6 = slices.Clone(info.DNSv6)
	info.DNSSuffix = slices.Clone(info.DNSSuffix)
	return contractnode.NodeExtraInfo{GlobalProtect: &info}
}

func secondsDuration(seconds int) time.Duration {
	if seconds <= 0 {
		return 0
	}
	maxSeconds := int64((1<<63 - 1) / int64(time.Second))
	if int64(seconds) > maxSeconds {
		return time.Duration(1<<63 - 1)
	}
	return time.Duration(seconds) * time.Second
}

func connectTunnel(ctx context.Context, c *control, s session, path string) (*tls.Conn, error) {
	u, err := url.Parse(path)
	if err != nil || u.IsAbs() || u.Host != "" || u.Path == "" || u.Path[0] != '/' {
		return nil, errors.New("globalprotect: invalid SSL tunnel path")
	}
	q := u.Query()
	q.Set("user", s.User)
	q.Set("authcookie", s.Cookie)
	u.RawQuery = q.Encode()

	conn, err := c.dialTLS(ctx)
	if err != nil {
		return nil, err
	}
	stopCloseOnCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCloseOnCancel()
	success := false
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	request := fmt.Appendf(nil, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: PAN GlobalProtect\r\n\r\n", u.RequestURI(), c.gateway.Host)
	if err := writeFull(conn, request); err != nil {
		return nil, err
	}
	var response [12]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return nil, err
	}
	if string(response[:]) != "START_TUNNEL" {
		responsePrefix := string(response[:])
		switch {
		case strings.HasPrefix(responsePrefix, "HTTP/") && strings.Contains(responsePrefix, " 512"):
			return nil, ErrInvalidAuthCookie
		case strings.HasPrefix(responsePrefix, "HTTP/") && strings.Contains(responsePrefix, " 513"):
			return nil, errors.New("globalprotect: gateway requires an unsupported client certificate")
		case strings.HasPrefix(responsePrefix, "HTTP/") && strings.Contains(responsePrefix, " 30"):
			return nil, errors.New("globalprotect: gateway redirected to a portal or interactive login flow, which is unsupported")
		}
		return nil, errors.New("globalprotect: SSL tunnel not accepted by gateway")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	if !stopCloseOnCancel() {
		return nil, ctx.Err()
	}
	success = true
	return conn, nil
}

func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n < 0 || n > len(data) {
			return errors.New("globalprotect: invalid write count")
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (c *Client) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	if err := c.stateError(); err != nil {
		return nil, err
	}
	conn, err := c.dialer.DialHappyEyeballsv2(ctx, addr)
	if err != nil {
		return nil, err
	}
	return wireguard.NewWrapGoNetTcpConn(conn), nil
}

func (c *Client) PacketConn(ctx context.Context, _ netapi.Address) (net.PacketConn, error) {
	if err := c.stateError(); err != nil {
		return nil, err
	}
	conn, err := c.tunnel.DialUDP(nil, nil)
	if err != nil {
		return nil, err
	}
	return wireguard.NewWrapGoNetUdpConn(context.WithoutCancel(ctx), conn), nil
}

func (c *Client) Ping(context.Context, netapi.Address) (uint64, error) {
	return 0, errors.ErrUnsupported
}

func (c *Client) stateError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failure != nil {
		return c.failure
	}
	if c.closed.Load() {
		return net.ErrClosed
	}
	return nil
}

func (c *Client) fail(err error) {
	if err == nil || c.closed.Load() {
		return
	}
	c.mu.Lock()
	if c.failure == nil {
		c.failure = err
	}
	c.mu.Unlock()
	log.Warn("globalprotect tunnel ended", "error", err)
	_ = c.Close()
}

func (c *Client) sendFrame(frame []byte) error {
	for {
		c.writeMu.Lock()
		if c.closed.Load() {
			c.writeMu.Unlock()
			return net.ErrClosed
		}
		conn, _ := c.currentConn()
		if conn == nil {
			c.writeMu.Unlock()
			return net.ErrClosed
		}
		err := writeFull(conn, frame)
		c.writeMu.Unlock()
		if err == nil {
			return nil
		}

		current, wait := c.currentConn()
		if current != conn {
			continue
		}
		if wait == nil {
			return err
		}
		select {
		case <-c.ctx.Done():
			return net.ErrClosed
		case <-wait:
		}
		if current, _ := c.currentConn(); current == conn {
			return err
		}
	}
}

func (c *Client) sendPackets() {
	slab := make([]byte, c.mtu+2*tun.ReadPacketSpacing)
	packets := make([]tun.ReadPacket, 1)
	for {
		n, err := c.tunnel.Read(slab, packets)
		if err != nil {
			if c.ctx.Err() == nil {
				c.fail(err)
			}
			return
		}
		for _, p := range packets[:n] {
			if p.Offset < 0 || p.Size < 1 || p.Offset+p.Size > len(slab) {
				c.fail(errors.New("globalprotect: invalid outgoing packet bounds"))
				return
			}
			c.touchActivity()
			if c.esp != nil {
				if err := c.esp.send(slab[p.Offset : p.Offset+p.Size]); err != nil {
					c.fail(err)
					return
				}
				continue
			}
			frame, err := encodeFrame(slab[p.Offset : p.Offset+p.Size])
			if err == nil {
				err = c.sendFrame(frame)
			}
			if err != nil {
				c.fail(err)
				return
			}
		}
	}
}

func (c *Client) receivePackets() {
	for {
		conn, _ := c.currentConn()
		if conn == nil {
			return
		}
		packet, isDPD, err := readFrame(conn)
		if err != nil {
			if c.ctx.Err() != nil {
				return
			}
			current, wait := c.currentConn()
			if current != conn {
				continue
			}
			if wait != nil {
				select {
				case <-c.ctx.Done():
					return
				case <-wait:
				}
				if current, _ := c.currentConn(); current != conn {
					continue
				}
			}
			c.fail(err)
			return
		}
		if isDPD {
			c.lastDPD.Store(time.Now().UnixNano())
			continue
		}
		c.touchActivity()
		if _, err := c.tunnel.Write([][]byte{packet}, 0); err != nil {
			if c.ctx.Err() != nil {
				return
			}
			log.Debug("globalprotect: dropping packet rejected by IP stack", "error", err)
			continue
		}
	}
}

func (c *Client) keepalive() {
	ticker := time.NewTicker(globalprotectDPDInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			lastDPD := time.Unix(0, c.lastDPD.Load())
			if dpdResponseTimedOut(time.Now(), lastDPD) {
				c.fail(errDPDTimeout)
				return
			}
			if c.esp != nil {
				if err := c.esp.send(activationPing(c.esp.local, c.esp.remote, 1)); err != nil {
					c.fail(err)
					return
				}
				continue
			}
			if err := c.sendFrame(dpdFrame()); err != nil {
				c.fail(err)
				return
			}
		}
	}
}

func dpdResponseTimedOut(now, lastResponse time.Time) bool {
	return now.Sub(lastResponse) >= globalprotectDPDTimeout
}

func (c *Client) touchActivity() { c.lastActivity.Store(time.Now().UnixNano()) }

func (c *Client) expireIdleAfter(d time.Duration) {
	if d <= 0 {
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			last := time.Unix(0, c.lastActivity.Load())
			if time.Since(last) >= d {
				c.fail(errGatewayIdleDisconnect)
				return
			}
		}
	}
}

func (c *Client) expireSessionAfter(d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		c.fail(errors.New("globalprotect: authentication lifetime elapsed; reconnect to authenticate again"))
	case <-c.ctx.Done():
	}
}

func (c *Client) rekeyAfter(timeout time.Duration) {
	if timeout <= 0 {
		return
	}
	delay := timeout - time.Minute
	if delay <= 0 {
		delay = timeout / 2
	}
	if delay < time.Second {
		delay = time.Second
	}
	for {
		timer := time.NewTimer(delay)
		select {
		case <-c.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if err := c.rekeyTunnel(); err != nil {
			if c.ctx.Err() == nil {
				c.fail(fmt.Errorf("globalprotect: tunnel rekey failed: %w", err))
			}
			return
		}
	}
}

func (c *Client) rekeyTunnel() error {
	if c.ctx.Err() != nil {
		return c.ctx.Err()
	}
	wait := make(chan struct{})
	c.connMu.Lock()
	c.rekeyWait = wait
	c.connMu.Unlock()
	defer func() {
		c.connMu.Lock()
		if c.rekeyWait == wait {
			c.rekeyWait = nil
		}
		close(wait)
		c.connMu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(c.ctx, 25*time.Second)
	defer cancel()
	conn, err := connectTunnel(ctx, c.control, c.session, c.tunnelURL)
	if err != nil {
		return err
	}
	if c.ctx.Err() != nil {
		_ = conn.Close()
		return c.ctx.Err()
	}

	c.writeMu.Lock()
	c.connMu.Lock()
	if c.closed.Load() {
		c.connMu.Unlock()
		c.writeMu.Unlock()
		_ = conn.Close()
		return net.ErrClosed
	}
	old := c.conn
	c.conn = conn
	c.connMu.Unlock()
	c.writeMu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return nil
}

func (c *Client) currentConn() (*tls.Conn, chan struct{}) {
	c.connMu.RLock()
	defer c.connMu.RUnlock()
	return c.conn, c.rekeyWait
}

func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.cancel()
		if c.esp != nil {
			_ = c.esp.socket.Close()
		}
		c.connMu.Lock()
		conn := c.conn
		c.conn = nil
		c.connMu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
		_ = c.tunnel.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := c.control.logout(ctx, c.session); err != nil {
			log.Debug("globalprotect logout failed", "error", err)
		}
		c.control.close()
		if c.done != nil {
			close(c.done)
		}
	})
	return nil
}
