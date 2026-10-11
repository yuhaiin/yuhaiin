package anyconnect

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/vlog"
)

// tunIO is the userspace TUN the data path reads IP from and writes IP to.
// *dataplane.TUN satisfies it; tests supply a fake.
type tunIO interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
}

// ErrAuth reports credentials the gateway rejected, so a caller can tell a
// wrong password from an unreachable server. The facade maps it onto
// client.ErrAuth, and two callers act on that: `veepin connect -retry` stops
// rather than retrying a password into a lockout, and the NetworkManager plugin
// reports LoginFailed so NM re-prompts instead of reporting a dead network.
//
// Exhausting maxAuthRounds counts as a rejection. A server that keeps
// re-presenting the same form is refusing the credential; it just refuses by
// asking again rather than by saying no, and treating that as a transport fault
// is what makes a retry loop hammer it.
var ErrAuth = errors.New("anyconnect: authentication failed")

// maxAuthRounds bounds the credential exchange. Servers differ in how many forms
// they present — one asking for username and password together, or two in
// sequence — so the client loops, and this stops a server that keeps re-asking
// from looping forever.
const maxAuthRounds = 8

// ClientConfig configures the AnyConnect client engine.
type ClientConfig struct {
	// Host is the server as it appears in the Host header and TLS SNI, without a
	// port unless it is non-standard.
	Host string
	// Hostname is the local name reported to the server, which shows it in its
	// session list. Cosmetic.
	Hostname string
	Username string
	Password string
	// BaseMTU is the path MTU the client reports; the server's reply may lower it.
	BaseMTU int
	// NoDTLS keeps the tunnel on TLS even when the server offers a UDP channel.
	NoDTLS bool
	Logger *vlog.Logger
}

// Client is a running AnyConnect tunnel over one TLS connection: it
// authenticates, issues CONNECT, and then moves IP packets between the TUN and
// the CSTP data channel.
type Client struct {
	cfg    ClientConfig
	conn   net.Conn
	br     *bufio.Reader
	tun    tunIO
	logger *vlog.Logger

	// writeMu serializes writes: the TUN pump, the keepalive timer and DPD
	// replies all send on the same connection.
	writeMu sync.Mutex

	// drops counts inbound packets the TUN refused, which is normal before the
	// caller has configured the interface.
	drops atomic.Uint64

	// dtls is the optional UDP data channel. When it is up, data packets go over
	// it and the TLS connection carries only control traffic; when it fails, the
	// tunnel falls back to TLS without interruption.
	dtls atomic.Pointer[dtlsChannel]

	dtlsParams DTLSParams

	// dpd is the outstanding dead-peer-detection probe, or nil. AnyConnect's
	// DPD is a request the peer must echo verbatim, so the probe is identified
	// by its payload rather than by a sequence number the protocol does not
	// carry.
	dpd atomic.Pointer[dpdProbe]

	mu       sync.Mutex
	closed   bool
	closeErr error
	done     chan struct{}
}

// NewClient builds a client over an established TLS connection and a TUN. The
// connection must already be authenticated at the TLS layer; this drives the
// HTTP exchange on top of it.
func NewClient(conn net.Conn, tun tunIO, cfg ClientConfig) *Client {
	logger := cfg.Logger
	return &Client{
		cfg:    cfg,
		conn:   conn,
		br:     bufio.NewReaderSize(conn, maxPayload+headerLen),
		tun:    tun,
		logger: logger,
		done:   make(chan struct{}),
	}
}

// Handshake authenticates and opens the tunnel, returning the addressing the
// server assigned. It does not start the data path; call Run for that.
func (c *Client) Handshake() (TunnelConfig, error) {
	cookie, err := c.authenticate()
	if err != nil {
		return TunnelConfig{}, err
	}
	c.logger.Printf("anyconnect: authenticated as %s", c.cfg.Username)
	return c.connect(cookie)
}

// StartDTLS brings up the UDP data channel if the server offered one. It is
// separate from Handshake because the tunnel is already usable without it: a
// failure here downgrades to TLS rather than failing the connection, and is
// reported only in the log.
func (c *Client) StartDTLS() {
	if !c.dtlsParams.Enabled || c.cfg.NoDTLS {
		return
	}
	ch, err := dialDTLS(c.conn, c.dtlsParams, dtlsHandshakeTimeout)
	if err != nil {
		c.logger.Printf("anyconnect: DTLS unavailable, staying on TLS: %v", err)
		return
	}
	c.dtls.Store(ch)
	c.logger.Printf("anyconnect: DTLS data channel up on udp/%d", c.dtlsParams.Port)
	go c.dtlsReadLoop(ch)
}

// dtlsHandshakeTimeout bounds bringing up the UDP channel. It is short: the
// tunnel already works over TLS, so a slow or filtered UDP path should be
// abandoned quickly rather than delaying a working connection.
const dtlsHandshakeTimeout = 5 * time.Second

// dtlsReadLoop delivers packets arriving on the UDP channel. Its failure is not
// the tunnel's: the channel is torn down and traffic returns to TLS.
func (c *Client) dtlsReadLoop(ch *dtlsChannel) {
	buf := make([]byte, maxPayload)
	for {
		n, err := ch.conn.Read(buf)
		if err != nil {
			if ch.up.Swap(false) {
				c.logger.Printf("anyconnect: DTLS channel lost, falling back to TLS: %v", err)
				c.dtls.CompareAndSwap(ch, nil)
				ch.close()
			}
			return
		}
		typ, payload, ok := parseDTLS(buf[:n])
		if !ok {
			continue
		}
		switch typ {
		case typeData:
			// Trim the server's downstream shaping padding, if any: the packet
			// the TUN gets is the one the IP header declares.
			inner := dataplane.TrimToIP(payload)
			if inner == nil {
				continue
			}
			if _, err := c.tun.Write(inner); err != nil {
				c.noteDrop(err)
			}
		case typeDPDReq:
			_ = ch.send(typeDPDResp, payload)
		case typeDPDResp:
			c.matchDPD(payload)
		}
	}
}

// authenticate runs the XML credential exchange and returns the session cookie.
func (c *Client) authenticate() (string, error) {
	msg := initMessage()
	for round := range maxAuthRounds {
		path := "/"
		if round > 0 {
			path = authPath
		}
		resp, body, err := c.postXML(path, msg)
		if err != nil {
			return "", err
		}
		reply, err := parseConfigAuth(body)
		if err != nil {
			return "", err
		}
		switch reply.Type {
		case "complete":
			if cookie := sessionCookieFrom(resp, reply); cookie != "" {
				return cookie, nil
			}
			return "", errors.New("anyconnect: server completed authentication without a session cookie")
		case "auth-request":
			if reply.Auth.Error != "" {
				return "", fmt.Errorf("%w: %s", ErrAuth, reply.Auth.Error)
			}
			if reply.Auth.Form == nil || len(reply.Auth.Form.Inputs) == 0 {
				return "", errors.New("anyconnect: server asked for credentials but presented no form")
			}
			msg = answerForm(reply.Auth.Form, c.cfg.Username, c.cfg.Password)
		default:
			return "", fmt.Errorf("anyconnect: unexpected auth message type %q", reply.Type)
		}
	}
	return "", fmt.Errorf("%w: did not complete in %d rounds", ErrAuth, maxAuthRounds)
}

// sessionCookieFrom finds the session token, which servers deliver either as a
// Set-Cookie header or in the completion message's session-token element.
func sessionCookieFrom(resp *http.Response, reply configAuth) string {
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookie && ck.Value != "" {
			return ck.Value
		}
	}
	return reply.SessionToken
}

// postXML sends one message of the authentication exchange and reads its reply.
func (c *Client) postXML(path string, msg configAuth) (*http.Response, []byte, error) {
	body, err := marshalConfigAuth(msg)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequest(http.MethodPost, "https://"+c.cfg.Host+path, bytes.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("anyconnect: build %s request: %w", msg.Type, err)
	}
	req.Host = c.cfg.Host
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ContentLength = int64(len(body))

	if err := req.Write(c.conn); err != nil {
		return nil, nil, fmt.Errorf("anyconnect: send %s: %w", msg.Type, err)
	}
	resp, err := http.ReadResponse(c.br, req)
	if err != nil {
		return nil, nil, fmt.Errorf("anyconnect: read %s reply: %w", msg.Type, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("anyconnect: read %s body: %w", msg.Type, err)
	}
	// 401/403 on the credential exchange is the server refusing the login, not a
	// transport fault; the server role answers a bad password with exactly that
	// (server.go's writeStatus(StatusUnauthorized)). Every other status is a
	// server problem the caller should retry.
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, nil, fmt.Errorf("%w: %s returned %s", ErrAuth, msg.Type, resp.Status)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("anyconnect: %s returned %s", msg.Type, resp.Status)
	}
	return resp, respBody, nil
}

// connect issues the CONNECT that converts the connection into a tunnel.
func (c *Client) connect(cookie string) (TunnelConfig, error) {
	baseMTU := c.cfg.BaseMTU
	if baseMTU == 0 {
		baseMTU = defaultMTU
	}
	hostname := c.cfg.Hostname
	if hostname == "" {
		hostname = "veepin"
	}
	if _, err := c.conn.Write(buildConnectRequest(c.cfg.Host, cookie, hostname, baseMTU)); err != nil {
		return TunnelConfig{}, fmt.Errorf("anyconnect: send CONNECT: %w", err)
	}
	// The request is handed to ReadResponse only so it knows this was a CONNECT,
	// which is what stops net/http treating the tunnel as a response body.
	resp, err := http.ReadResponse(c.br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return TunnelConfig{}, fmt.Errorf("anyconnect: read CONNECT reply: %w", err)
	}
	// A CONNECT response has no body to consume — the connection becomes the
	// tunnel — so the body is closed without reading.
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return TunnelConfig{}, fmt.Errorf("anyconnect: CONNECT refused: %s", resp.Status)
	}
	cfg, err := parseTunnelConfig(resp.Header)
	if err != nil {
		return TunnelConfig{}, err
	}
	// A malformed or unsupported DTLS offer only costs the UDP channel; the
	// tunnel itself is already established over TLS.
	if p, derr := parseDTLSParams(resp.Header, cfg.MTU); derr != nil {
		c.logger.Printf("anyconnect: ignoring the DTLS offer: %v", derr)
	} else {
		c.dtlsParams = p
	}
	c.logger.Printf("anyconnect: tunnel up, address %s netmask %s mtu %d", cfg.Address, cfg.Netmask, cfg.MTU)
	return cfg, nil
}

// Run moves packets until the tunnel closes. It blocks.
func (c *Client) Run(keepalive time.Duration) error {
	go c.tunLoop()
	if keepalive > 0 {
		go c.keepaliveLoop(keepalive)
	}
	c.readLoop()
	<-c.done
	return c.closeErr
}

// readLoop reads CSTP packets and dispatches them.
func (c *Client) readLoop() {
	for {
		typ, payload, err := readPacket(c.br)
		if err != nil {
			c.fail(fmt.Errorf("anyconnect: read: %w", err))
			return
		}
		switch typ {
		case typeData:
			// A packet the TUN will not take is a dropped packet, not a dead
			// tunnel. Dial deliberately installs no host configuration — that is
			// the caller's job once it has the Result — so there is a window after
			// the handshake in which the interface exists but is still down, and
			// Linux answers a write to a down TUN with EIO. Treating that as fatal
			// tore the whole session down over one early inbound packet, which is
			// how a slower machine turned a routine race into a dead VPN.
			//
			// TrimToIP drops the server's downstream shaping padding, if any.
			inner := dataplane.TrimToIP(payload)
			if inner == nil {
				continue
			}
			if _, err := c.tun.Write(inner); err != nil {
				c.noteDrop(err)
				continue
			}
		case typeDPDReq:
			// A DPD probe must be echoed with its payload intact, which is also how
			// the peer measures path MTU.
			if err := c.send(typeDPDResp, payload); err != nil {
				c.fail(err)
				return
			}
		case typeDPDResp:
			c.matchDPD(payload)
		case typeKeepalive:
		case typeDisconnect, typeTerminate:
			c.fail(fmt.Errorf("anyconnect: server closed the session"))
			return
		case typeCompressed:
			c.fail(errors.New("anyconnect: server sent compressed data, which was not negotiated"))
			return
		}
	}
}

// tunLoop pumps IP packets from the TUN into the tunnel.
func (c *Client) tunLoop() {
	buf := make([]byte, maxPayload)
	for {
		n, err := c.tun.Read(buf)
		if err != nil {
			c.fail(fmt.Errorf("anyconnect: TUN read: %w", err))
			return
		}
		// Forward IPv4 only. The session negotiated X-CSTP-Address-Type: IPv4 and
		// holds no IPv6 address, but Linux brings IPv6 up on a TUN the moment the
		// interface does and immediately emits MLD reports and router
		// solicitations to link-local multicast. Putting those on an IPv4-only
		// session is a protocol violation, and a server is entitled to answer it
		// by tearing the session down — which looks exactly like a tunnel that
		// dies the instant routing is applied.
		if !isIPv4(buf[:n]) {
			continue
		}
		// Prefer the UDP channel when it is up. A send failure on it demotes the
		// channel rather than the tunnel, and this packet goes out over TLS.
		if ch := c.dtls.Load(); ch != nil && ch.up.Load() {
			if err := ch.send(typeData, buf[:n]); err == nil {
				continue
			}
			if ch.up.Swap(false) {
				c.logger.Warnf("anyconnect: DTLS send failed, falling back to TLS")
				c.dtls.CompareAndSwap(ch, nil)
				ch.close()
			}
		}
		if err := c.send(typeData, buf[:n]); err != nil {
			c.fail(err)
			return
		}
	}
}

// noteDrop records an inbound packet the TUN would not accept. The first is
// logged with its reason, since a persistent fault (a closed device, a
// misconfigured MTU) should be visible; the rest are only counted, so a steady
// trickle cannot flood the log.
func (c *Client) noteDrop(err error) {
	if c.drops.Add(1) == 1 {
		c.logger.Warnf("anyconnect: dropping inbound packet: %v "+
			"(expected until the interface is configured)", err)
	}
}

// Drops reports how many inbound packets the TUN refused.
func (c *Client) Drops() uint64 { return c.drops.Load() }

// isIPv4 reports whether a packet read from the TUN is IPv4. A TUN carries bare
// IP with no link header, so the version nibble is the first thing in the frame.
func isIPv4(pkt []byte) bool {
	return len(pkt) >= 20 && pkt[0]>>4 == 4
}

// dpdProbe is one outstanding dead-peer-detection request: the payload the peer
// must echo, and the channel closed when it does.
type dpdProbe struct {
	payload []byte
	done    chan struct{}
}

// dpdPayloadLen is the size of a probe's nonce. AnyConnect's DPD carries an
// opaque payload the peer returns unchanged, so its only job is to be unlikely
// to collide with a probe the peer originated -- eight random octets is
// generous for a mechanism that has at most one request outstanding.
const dpdPayloadLen = 8

// ErrPeerSilent reports a dead-peer-detection probe the peer did not answer.
var ErrPeerSilent = errors.New("anyconnect: the peer did not answer dead-peer detection")

// Probe sends a DPD request on whichever carrier currently moves data and waits
// for the peer to echo it back.
//
// The carrier matters, and it is why the probe does not simply use the TLS
// connection. When DTLS is up, data goes over UDP while TLS carries only
// control traffic -- so a UDP path that has silently stopped (a NAT binding
// expiring is the ordinary way) loses every packet while the TLS connection
// sits there healthy and idle. Probing TLS would report that tunnel up. The
// read loop demotes the DTLS channel on a read *error*; silence is not an
// error, which is exactly the case this covers.
//
// This end has always echoed the peer's DPD requests and never sent one of its
// own, so the mechanism was half-built: it could prove this client alive to a
// server, and could learn nothing about the server.
func (c *Client) Probe(ctx context.Context) error {
	payload := make([]byte, dpdPayloadLen)
	if _, err := rand.Read(payload); err != nil {
		return fmt.Errorf("anyconnect: dpd nonce: %w", err)
	}
	p := &dpdProbe{payload: payload, done: make(chan struct{})}
	if !c.dpd.CompareAndSwap(nil, p) {
		// One probe at a time. A second concurrent call would make the echo
		// ambiguous, and the liveness monitor never issues one anyway.
		return errors.New("anyconnect: a dead-peer-detection probe is already outstanding")
	}
	defer c.dpd.CompareAndSwap(p, nil)

	var err error
	if ch := c.dtls.Load(); ch != nil && ch.up.Load() {
		err = ch.send(typeDPDReq, payload)
	} else {
		err = c.send(typeDPDReq, payload)
	}
	if err != nil {
		return err
	}

	select {
	case <-p.done:
		return nil
	case <-c.done:
		return ErrPeerSilent
	case <-ctx.Done():
		return fmt.Errorf("%w: %w", ErrPeerSilent, ctx.Err())
	}
}

// matchDPD releases the outstanding probe if this response is its echo. A
// response carrying anything else is ignored rather than treated as proof: the
// payload is the only thing tying an answer to a question here, so accepting a
// mismatched echo would let a stale reply keep a dead tunnel looking alive.
func (c *Client) matchDPD(payload []byte) {
	p := c.dpd.Load()
	if p == nil || !bytes.Equal(p.payload, payload) {
		return
	}
	select {
	case <-p.done: // already released
	default:
		close(p.done)
	}
}

// keepaliveLoop holds the connection open through idle NAT timeouts.
func (c *Client) keepaliveLoop(every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if err := c.send(typeKeepalive, nil); err != nil {
				c.fail(err)
				return
			}
		case <-c.done:
			return
		}
	}
}

func (c *Client) send(typ byte, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if _, err := c.conn.Write(marshal(typ, payload)); err != nil {
		return fmt.Errorf("anyconnect: write: %w", err)
	}
	return nil
}

// Close tears the tunnel down, sending a DISCONNECT so the server can release
// the session rather than waiting for the connection to time out.
func (c *Client) Close() error {
	c.mu.Lock()
	already := c.closed
	c.mu.Unlock()
	if !already {
		_ = c.send(typeDisconnect, []byte{0})
	}
	c.fail(nil)
	return c.closeErr
}

// fail closes the client once, recording the first error to arrive.
func (c *Client) fail(err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.closeErr = err
	c.mu.Unlock()

	close(c.done)
	if ch := c.dtls.Swap(nil); ch != nil {
		ch.close()
	}
	c.conn.Close()
}
