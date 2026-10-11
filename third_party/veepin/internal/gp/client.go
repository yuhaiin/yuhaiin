package gp

// The client engine: the HTTPS login, then whichever data path came back.
//
// Login is ordinary HTTP over the caller's TLS-configured http.Client. What
// follows is a choice the gateway made for us: if the configuration carried a
// keying block, the client tries ESP first and falls back to the SSL tunnel when
// the datagrams do not get through; without one there is only the SSL tunnel.
//
// The order matters and only works in that direction. Opening the SSL tunnel
// invalidates the SPIs the same configuration handed out, so a client that tried
// the tunnel first would have no ESP path left to fall back *to*.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/ikev2/esp"
	"github.com/xen0bit/veepin/internal/vlog"
)

// ErrAuth reports rejected credentials, so a caller can tell a bad password from
// a transport failure.
var ErrAuth = errors.New("gp: authentication failed")

// ErrSAML reports a gateway that wants browser-based authentication, which this
// client cannot do. It is named separately so the failure does not look like a
// wrong password.
var ErrSAML = errors.New("gp: the gateway requires SAML authentication")

// Timeouts for the two stages that can hang without failing.
const (
	// espActivationTimeout bounds the whole activation exchange before the client
	// gives up on ESP and falls back to the SSL tunnel.
	espActivationTimeout = 6 * time.Second
	// espProbeInterval is how long one activation ping waits for its answer.
	espProbeInterval = 2 * time.Second
)

// Login authenticates and fetches the tunnel configuration. base is the
// gateway's https:// origin; computer names this host in the gateway's logs.
func Login(hc *http.Client, base, user, password, computer string) (LoginInfo, Config, error) {
	// Prelogin is advisory — it tells the client what the gateway wants — but it
	// is where SAML is discovered, and discovering that here means failing with
	// the reason rather than with a rejected password.
	if pl, err := prelogin(hc, base); err == nil && pl.SAML {
		return LoginInfo{}, Config{}, ErrSAML
	}

	body, err := post(hc, base+PathLogin, BuildLoginForm(user, password, computer, ""))
	if err != nil {
		return LoginInfo{}, Config{}, err
	}
	info, err := ParseLoginResponse(body)
	if err != nil {
		// A gateway that rejects credentials answers with an HTML error page, not
		// a jnlp document, so a parse failure here is an authentication failure.
		return LoginInfo{}, Config{}, fmt.Errorf("%w: %v", ErrAuth, err)
	}
	if info.User == "" {
		info.User = user
	}

	body, err = post(hc, base+PathGetConfig, BuildGetConfigForm(info, computer))
	if err != nil {
		return LoginInfo{}, Config{}, err
	}
	cfg, err := ParseConfigXML(body)
	if err != nil {
		return LoginInfo{}, Config{}, err
	}
	if cfg.AssignedIP == nil {
		return LoginInfo{}, Config{}, errors.New("gp: the gateway assigned no address")
	}
	return info, cfg, nil
}

// prelogin asks what the gateway wants. A gateway that does not answer is not a
// failure on its own: the login attempt that follows is the real test.
func prelogin(hc *http.Client, base string) (Prelogin, error) {
	body, err := post(hc, base+PathPrelogin, "tmp=tmp&clientVer="+clientVersion+"&clientos=Linux")
	if err != nil {
		return Prelogin{}, err
	}
	return ParsePreloginResponse(body)
}

// post submits a form and returns the body, mapping the status codes a gateway
// uses to refuse a login onto ErrAuth.
func post(hc *http.Client, url, form string) ([]byte, error) {
	resp, err := hc.Post(url, "application/x-www-form-urlencoded", strings.NewReader(form))
	if err != nil {
		return nil, fmt.Errorf("gp: %s: %w", url, err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return body, nil
	case http.StatusForbidden, http.StatusUnauthorized:
		return nil, fmt.Errorf("%w: gateway returned %s", ErrAuth, resp.Status)
	default:
		return nil, fmt.Errorf("gp: %s returned %s", url, resp.Status)
	}
}

// Logout ends the session. Failures are the caller's to ignore: the tunnel is
// already down by the time this runs, and a gateway that does not answer will
// expire the session on its own.
func Logout(hc *http.Client, base string, info LoginInfo, computer string) error {
	_, err := post(hc, base+PathLogout, BuildLogoutForm(info, computer))
	return err
}

// Client is an established GlobalProtect tunnel. Exactly one of its two data
// paths is running.
type Client struct {
	cfg Config

	// The SSL tunnel path.
	link *tunnelLink

	// The ESP path.
	pump    *dataplane.Pump
	espConn *net.UDPConn
	done    chan struct{}
	err     error
}

// AssignedConfig is the configuration the login returned.
func (c *Client) AssignedConfig() Config { return c.cfg }

// OverESP reports which data path is carrying traffic, for logs and tests.
func (c *Client) OverESP() bool { return c.pump != nil }

// RunSSL drives the SSL tunnel over conn and binds it to tun. conn must already
// have had the tunnel request written to it and its START_TUNNEL answer read.
func RunSSL(conn net.Conn, cfg Config, tun io.ReadWriteCloser, logger *vlog.Logger) (*Client, error) {
	link := newLink(conn, nil, tun, logger)
	link.ownsTUN = true
	go link.readLoop()
	go link.tunLoop()
	return &Client{cfg: cfg, link: link}, nil
}

// ReadTunnelStart consumes the gateway's answer to the tunnel request. The
// gateway writes a bare marker rather than an HTTP status line, so anything else
// on the connection is an error page and must not be framed as packets.
func ReadTunnelStart(conn net.Conn) error {
	buf := make([]byte, len(TunnelStart))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("gp: reading the tunnel response: %w", err)
	}
	if string(buf) != TunnelStart {
		return fmt.Errorf("gp: the gateway refused the tunnel: %q", strings.TrimSpace(string(buf)))
	}
	return nil
}

// RunESP brings the ESP data path up: it activates the path, then runs a pump
// over it. It returns an error the caller is expected to treat as "fall back to
// the SSL tunnel" rather than as fatal — a blocked UDP port is the ordinary
// reason, and the SSL tunnel is what the protocol keeps for it.
//
// shape is the per-flow shaping budget in bytes; 0 disables shaping.
func RunESP(cfg Config, tun io.ReadWriteCloser, logger *vlog.Logger, shape, mtu int) (*Client, error) {
	if logger == nil {
		logger = vlog.Discard()
	}
	if cfg.ESP == nil {
		return nil, errors.New("gp: the gateway offered no ESP keys")
	}
	if cfg.GatewayAddr == nil {
		return nil, errors.New("gp: the gateway named no ESP address")
	}
	sa, err := cfg.ESP.NewSA(true)
	if err != nil {
		return nil, err
	}

	port := cfg.ESP.UDPPort
	if port == 0 {
		port = DefaultESPPort
	}
	peer := &net.UDPAddr{IP: cfg.GatewayAddr, Port: port}
	conn, err := net.DialUDP("udp", nil, peer)
	if err != nil {
		return nil, fmt.Errorf("gp: dialing the ESP path: %w", err)
	}

	if err := activateESP(conn, sa, cfg.AssignedIP, cfg.GatewayAddr); err != nil {
		_ = conn.Close()
		return nil, err
	}

	c := &Client{cfg: cfg, espConn: conn, done: make(chan struct{})}
	send := func(pkt []byte, _ *net.UDPAddr) {
		if _, err := conn.Write(pkt); err != nil {
			c.stop(err)
		}
	}
	c.pump = dataplane.NewPump(tun, send, dataplane.SPIDemux, logger.Slog())
	if mtu > 0 {
		c.pump.SetInnerMTU(mtu)
	}
	if shape > 0 {
		c.pump.SetShaper(dataplane.NewShaper(dataplane.ShapeConfig{Bytes: shape}))
		logger.Printf("gp: outbound shaping on, %d bytes per flow", shape)
	}
	// One tunnel carrying everything: a client has exactly one gateway, and the
	// caller decides from client.Result whether that becomes a default route.
	c.pump.AddTunnel(NewTunnel(sa, cfg.ESP.S2CSPI, defaultRoutes(), peer))

	go c.pump.Run()
	go c.readESP()
	return c, nil
}

// defaultRoutes is every destination, both families: what a client's single
// tunnel to its gateway carries.
func defaultRoutes() []netip.Prefix {
	return []netip.Prefix{
		netip.PrefixFrom(netip.IPv4Unspecified(), 0),
		netip.PrefixFrom(netip.IPv6Unspecified(), 0),
	}
}

// activateESP wakes the gateway's ESP path up and proves it carries traffic in
// both directions. A gateway ignores ESP from a client it has not heard from, so
// silence here is the normal signal that the path is unusable — not an error to
// retry forever.
func activateESP(conn *net.UDPConn, sa *esp.SA, src, dst net.IP) error {
	buf := make([]byte, 2048)
	deadline := time.Now().Add(espActivationTimeout)
	for seq := 1; seq <= activationPings && time.Now().Before(deadline); seq++ {
		ping, err := BuildActivationPing(src, dst, uint16(seq))
		if err != nil {
			return err
		}
		pkt, err := sa.Encapsulate(ping, 4)
		if err != nil {
			return fmt.Errorf("gp: protecting the activation ping: %w", err)
		}
		if _, err := conn.Write(pkt); err != nil {
			return fmt.Errorf("gp: sending the activation ping: %w", err)
		}

		wait := min(espProbeInterval, time.Until(deadline))
		if wait <= 0 {
			break
		}
		if err := conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
			return err
		}
		for {
			n, err := conn.Read(buf)
			if err != nil {
				break // the deadline expired; send the next probe
			}
			// Anything that opens under our own inbound SA is proof the gateway
			// answered. The reply itself is dropped: it is a probe, not traffic.
			if _, _, err := sa.Decapsulate(buf[:n]); err == nil {
				_ = conn.SetReadDeadline(time.Time{})
				return nil
			}
		}
	}
	return errors.New("gp: the gateway did not answer on the ESP path")
}

// readESP feeds inbound datagrams to the pump.
func (c *Client) readESP() {
	buf := make([]byte, maxInnerPacket)
	for {
		n, err := c.espConn.Read(buf)
		if err != nil {
			c.stop(err)
			return
		}
		c.pump.HandleInbound(buf[:n], nil)
	}
}

// stop ends the ESP path once, recording the first cause.
func (c *Client) stop(cause error) {
	select {
	case <-c.done:
		return
	default:
	}
	c.err = cause
	close(c.done)
	c.pump.Close()
	_ = c.espConn.Close()
}

// Wait blocks until the tunnel stops.
func (c *Client) Wait() error {
	if c.link != nil {
		return c.link.Wait()
	}
	<-c.done
	return c.err
}

// Close tears the tunnel down.
func (c *Client) Close() error {
	if c.link != nil {
		return c.link.Close()
	}
	c.stop(nil)
	return nil
}

// probeIdle is how long the ESP path may go without an authenticated inbound
// packet before a probe calls it dead. The gateway answers the activation pings
// and any traffic, so a live path is never idle this long under load; an idle one
// is confirmed by the probe that follows.
const probeIdle = 30 * time.Second

// Probe implements client.Prober: it establishes whether the far end is still
// there, so a dead gateway tears the tunnel down instead of blackholing it.
//
// The two data paths need different evidence. On the SSL tunnel the liveness
// packet is the protocol's own keepalive, which the gateway echoes. On the ESP
// path there is no keepalive to send that the gateway would answer once it is
// past activation, so the pump's own record of authenticated inbound traffic is
// what is consulted.
func (c *Client) Probe(ctx context.Context) error {
	if c.pump != nil {
		if idle := c.pump.IdleFor(); idle > probeIdle {
			return fmt.Errorf("gp: no authenticated ESP for %s", idle.Truncate(time.Second))
		}
		return nil
	}

	// Drain any staleness so the wait below is evidence about now.
	select {
	case <-c.link.alive:
	default:
	}
	if err := c.link.sendKeepalive(); err != nil {
		return err
	}
	select {
	case <-c.link.alive:
		return nil
	case <-c.link.done:
		return c.link.err
	case <-ctx.Done():
		return ctx.Err()
	}
}
