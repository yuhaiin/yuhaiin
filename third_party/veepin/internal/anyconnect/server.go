package anyconnect

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/dtls"
	"github.com/xen0bit/veepin/internal/userdb"
	"github.com/xen0bit/veepin/internal/vlog"
)

// handshakeTimeout bounds the HTTP authentication and CONNECT exchange. Once the
// tunnel is up the connection carries data with no deadline.
const handshakeTimeout = 30 * time.Second

// Server-advertised liveness intervals, in seconds. DPD is what a client uses to
// notice a dead path; the keepalive holds an idle NAT binding open.
const (
	serverDPD       = 30
	serverKeepalive = 20
)

// ServerConfig configures the AnyConnect server engine.
type ServerConfig struct {
	Users   map[string]string // username -> password
	Pool    *dataplane.AddrPool
	Gateway net.IP // the server's inner address (the pool's first host)
	DNS     []net.IP
	MTU     int
	// Shape enables downstream traffic shaping: how much padded output each
	// inner flow is given before shaping stops for that flow, so it bounds what
	// shaping costs. A flow gets Shape/MTU padded packets whatever sizes it
	// carries. Zero, the default, disables it. See dataplane/shape.go.
	Shape int
	// DTLSConn is the UDP socket offering the DTLS data channel. Nil serves TLS
	// only, which is a complete tunnel — the protocol treats TLS as the fallback
	// whenever UDP is unavailable.
	DTLSConn *net.UDPConn
	Logger   *vlog.Logger
}

// Server is a running AnyConnect responder. Like SSTP it is connection-oriented:
// each client rides its own TLS connection and gets one goroutine, and all share
// a single TUN routed by inner destination address.
type Server struct {
	cfg     ServerConfig
	tun     tunIO
	pool    *dataplane.AddrPool
	gateway net.IP
	logger  *vlog.Logger

	sessions sync.Map

	lock    sync.Mutex
	clients map[uint32]*serverClient // keyed by assigned inner address

	dtls *dtlsListener

	// shaper decides which outbound packets are padded to the tunnel MTU. It is
	// unsynchronised, which is safe because tunLoop is the one goroutine that
	// touches it — every client's downstream traffic leaves through there.
	shaper *dataplane.Shaper

	done      chan struct{}
	closeOnce sync.Once
}

// NewServer builds a server over a TUN. Connections are handed to Serve by the
// caller, which owns the listener.
func NewServer(tun tunIO, cfg ServerConfig) *Server {
	logger := cfg.Logger
	s := &Server{
		cfg:     cfg,
		tun:     tun,
		pool:    cfg.Pool,
		gateway: cfg.Gateway,
		logger:  logger,
		clients: map[uint32]*serverClient{},
		done:    make(chan struct{}),
	}
	if cfg.DTLSConn != nil {
		s.dtls = newDTLSListener(cfg.DTLSConn, logger)
	}
	if cfg.Shape > 0 {
		s.shaper = dataplane.NewShaper(dataplane.ShapeConfig{Bytes: cfg.Shape})
		logger.Printf("anyconnect: downstream shaping on, %d bytes per flow", cfg.Shape)
	}
	return s
}

// Start begins routing TUN egress to connected clients, and accepting DTLS flows
// if a UDP socket was provided.
func (s *Server) Start() {
	go s.tunLoop()
	if s.dtls != nil {
		go s.dtls.serve()
	}
}

// Close stops the server and drops every client.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		if s.dtls != nil {
			_ = s.dtls.close()
		}
		s.lock.Lock()
		for _, c := range s.clients {
			c.conn.Close()
		}
		s.lock.Unlock()
	})
	return nil
}

// ServeConn runs one client connection to completion. The caller supplies an
// established TLS connection; this drives the HTTP exchange and then the data
// path, and returns when the client disconnects.
func (s *Server) ServeConn(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReaderSize(conn, maxPayload+headerLen)

	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return
	}
	cookie, err := s.serveAuth(conn, br)
	if err != nil {
		s.logger.Warnf("anyconnect: %s: authentication failed: %v", conn.RemoteAddr(), err)
		return
	}
	c, err := s.serveConnect(conn, br, cookie)
	if err != nil {
		s.logger.Warnf("anyconnect: %s: CONNECT failed: %v", conn.RemoteAddr(), err)
		return
	}
	defer s.removeClient(c)

	// The tunnel is up; drop the handshake deadline.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return
	}
	s.logger.Printf("anyconnect: %s connected as %s, assigned %s",
		conn.RemoteAddr(), c.username, c.innerIP)
	c.readLoop()
}

// serveAuth runs the XML credential exchange, returning the session cookie the
// client must present on its CONNECT.
func (s *Server) serveAuth(conn net.Conn, br *bufio.Reader) (string, error) {
	for range maxAuthRounds {
		req, err := http.ReadRequest(br)
		if err != nil {
			return "", fmt.Errorf("read request: %w", err)
		}
		if req.Method != http.MethodPost {
			return "", fmt.Errorf("unexpected %s %s during authentication", req.Method, req.URL.Path)
		}
		body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		req.Body.Close()
		if err != nil {
			return "", fmt.Errorf("read body: %w", err)
		}
		msg, err := parseConfigAuth(body)
		if err != nil {
			return "", err
		}
		switch msg.Type {
		case "init":
			if err := writeXML(conn, credentialForm(), nil); err != nil {
				return "", err
			}
		case "auth-reply":
			user := msg.Auth.field("username")
			pass := msg.Auth.field("password")
			if !s.authenticate(user, pass) {
				// Re-present the form with an error rather than closing, which is
				// how the protocol reports a bad password.
				_ = writeXML(conn, failureMessage("Invalid credentials"), nil)
				return "", fmt.Errorf("bad credentials for %q", user)
			}
			cookie := newSessionToken()
			s.sessions.Store(cookie, user)
			var hdr headerList
			hdr.set("Set-Cookie", sessionCookie+"="+cookie+"; path=/; Secure")
			return cookie, writeXML(conn, completeMessage(cookie, cookie), hdr)
		default:
			return "", fmt.Errorf("unexpected auth message type %q", msg.Type)
		}
	}
	return "", fmt.Errorf("authentication did not complete in %d rounds", maxAuthRounds)
}

// authenticate checks a username and password in constant time with respect to
// the password, so a wrong password cannot be distinguished from a wrong one of
// a different length by timing. The stored secret may be a bcrypt verifier
// rather than the password -- this protocol receives the password and compares
// it, so it never needs to hold one (see internal/userdb).
func (s *Server) authenticate(user, pass string) bool {
	want, ok := s.cfg.Users[user]
	if !ok {
		// Still compare, so a valid username is not revealed by a faster reject.
		subtle.ConstantTimeCompare([]byte(pass), []byte(pass))
		return false
	}
	return userdb.Verify(want, pass)
}

// serveConnect answers the CONNECT request, allocating the client an address and
// replying with the configuration headers that carry it.
func (s *Server) serveConnect(conn net.Conn, br *bufio.Reader, cookie string) (*serverClient, error) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, fmt.Errorf("read CONNECT: %w", err)
	}
	req.Body.Close()
	if req.Method != http.MethodConnect {
		return nil, fmt.Errorf("expected CONNECT, got %s %s", req.Method, req.URL.Path)
	}
	user, ok := s.sessionUser(req, cookie)
	if !ok {
		_ = writeStatus(conn, http.StatusUnauthorized)
		return nil, fmt.Errorf("CONNECT without a valid session cookie")
	}

	ip, err := s.pool.Allocate()
	if err != nil {
		_ = writeStatus(conn, http.StatusServiceUnavailable)
		return nil, fmt.Errorf("address pool exhausted: %w", err)
	}

	mtu := s.mtu()
	cfg := TunnelConfig{
		Address: ip,
		Netmask: net.IP(s.pool.Network().Mask),
		DNS:     s.cfg.DNS,
		MTU:     mtu,
	}
	var hdr headerList
	writeTunnelConfig(&hdr, cfg, serverDPD, serverKeepalive)

	c := &serverClient{
		srv:      s,
		conn:     conn,
		br:       br,
		username: user,
		innerIP:  ip,
	}
	// Offer the UDP data channel if this server has a socket for it and the
	// client asked. A client that did not, or a TLS session whose exporter is
	// unavailable, simply gets no DTLS headers and stays on TLS.
	if s.dtls != nil && strings.Contains(strings.ToUpper(req.Header.Get(hdrDTLSCipherSuite)), "PSK") {
		if err := s.offerDTLS(conn, &hdr, c, mtu); err != nil {
			s.logger.Printf("anyconnect: not offering DTLS to %s: %v", conn.RemoteAddr(), err)
		}
	}

	if err := writeConnectOK(conn, hdr); err != nil {
		s.pool.Release(ip)
		return nil, err
	}
	s.addClient(c)
	return c, nil
}

// sessionUser validates the cookie the client presents on CONNECT against the
// one issued during authentication.
func (s *Server) sessionUser(req *http.Request, issued string) (string, bool) {
	for _, ck := range req.Cookies() {
		if ck.Name != sessionCookie {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(ck.Value), []byte(issued)) != 1 {
			continue
		}
		if user, ok := s.sessions.Load(ck.Value); ok {
			name, _ := user.(string)
			return name, true
		}
	}
	return "", false
}

func (s *Server) addClient(c *serverClient) {
	if v4 := c.innerIP.To4(); v4 != nil {
		s.lock.Lock()
		s.clients[binary.BigEndian.Uint32(v4)] = c
		s.lock.Unlock()
	}
}

func (s *Server) removeClient(c *serverClient) {
	if v4 := c.innerIP.To4(); v4 != nil {
		s.lock.Lock()
		delete(s.clients, binary.BigEndian.Uint32(v4))
		s.lock.Unlock()
	}
	if c.appID != "" && s.dtls != nil {
		s.dtls.forget(c.appID)
	}
	if ch := c.dtls.Swap(nil); ch != nil {
		ch.close()
	}
	s.pool.Release(c.innerIP)
	s.logger.Printf("anyconnect: %s disconnected, released %s", c.username, c.innerIP)
}

func (s *Server) clientByIP(ip net.IP) *serverClient {
	v4 := ip.To4()
	if v4 == nil {
		return nil
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.clients[binary.BigEndian.Uint32(v4)]
}

// mtu is the inner MTU offered to clients, and the size shaped packets are
// padded to.
func (s *Server) mtu() int {
	if s.cfg.MTU == 0 {
		return defaultMTU
	}
	return s.cfg.MTU
}

// tunLoop routes TUN egress to the client owning the inner destination address.
func (s *Server) tunLoop() {
	buf := make([]byte, maxPayload)
	mtu := s.mtu()
	pad := make([]byte, mtu) // scratch for shaped packets; see padPayload
	for {
		n, err := s.tun.Read(buf)
		if err != nil {
			return
		}
		dst := ipv4Dst(buf[:n])
		if dst == nil {
			continue
		}
		c := s.clientByIP(dst)
		if c == nil {
			continue
		}
		pkt := padPayload(pad, buf[:n], s.shaper.Target(buf[:n], mtu))
		// Prefer the UDP channel. A send failure on it demotes the channel, not
		// the client, and the packet goes out over TLS instead.
		if ch := c.dtls.Load(); ch != nil && ch.up.Load() {
			if err := ch.send(typeData, pkt); err == nil {
				continue
			}
			if ch.up.Swap(false) {
				c.dtls.CompareAndSwap(ch, nil)
				ch.close()
			}
		}
		_ = c.send(typeData, pkt)
	}
}

// serverClient is one connected client.
type serverClient struct {
	srv      *Server
	conn     net.Conn
	br       *bufio.Reader
	username string
	innerIP  net.IP
	appID    string

	// dtls is this client's UDP data channel once it comes up.
	dtls atomic.Pointer[dtlsChannel]

	writeMu sync.Mutex
}

// readLoop reads this client's packets until the connection ends.
func (c *serverClient) readLoop() {
	for {
		typ, payload, err := readPacket(c.br)
		if err != nil {
			return
		}
		switch typ {
		case typeData:
			// Only forward packets whose source is the address this client was
			// assigned, so one client cannot spoof another's traffic onto the TUN.
			if src := ipv4Src(payload); src == nil || !src.Equal(c.innerIP) {
				continue
			}
			// Trim any padding the peer added past the inner packet; a veepin
			// client shapes its upstream the same way this server shapes down.
			inner := dataplane.TrimToIP(payload)
			if inner == nil {
				continue
			}
			if _, err := c.srv.tun.Write(inner); err != nil {
				return
			}
		case typeDPDReq:
			if err := c.send(typeDPDResp, payload); err != nil {
				return
			}
		case typeDPDResp, typeKeepalive:
		case typeDisconnect, typeTerminate:
			return
		}
	}
}

func (c *serverClient) send(typ byte, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err := c.conn.Write(marshal(typ, payload))
	return err
}

// --- HTTP response helpers ---
//
// Responses are written by hand rather than through net/http's Server, because
// the connection stops being HTTP the moment CONNECT succeeds and has to be
// taken over for framed packets.

// writeXML sends an XML message of the authentication exchange.
func writeXML(w io.Writer, msg configAuth, extra headerList) error {
	body, err := marshalConfigAuth(msg)
	if err != nil {
		return err
	}
	h := append(headerList{}, extra...)
	h.set("Content-Type", "text/xml")
	h.setInt("Content-Length", len(body))
	h.set("Connection", "keep-alive")
	return writeResponse(w, http.StatusOK, "OK", h, body)
}

// writeConnectOK accepts the tunnel request. Its headers carry the client's
// configuration, and everything after them is CSTP framing.
func writeConnectOK(w io.Writer, h headerList) error {
	h.set("Content-Type", "application/octet-stream")
	h.set("Connection", "keep-alive")
	// No Content-Length: the body is the tunnel and never ends.
	return writeResponse(w, http.StatusOK, "Connection established", h, nil)
}

func writeStatus(w io.Writer, code int) error {
	var h headerList
	h.set("Content-Length", "0")
	return writeResponse(w, code, http.StatusText(code), h, nil)
}

func writeResponse(w io.Writer, code int, reason string, h headerList, body []byte) error {
	var buf []byte
	buf = append(buf, fmt.Sprintf("HTTP/1.1 %d %s\r\n", code, reason)...)
	for _, kv := range h {
		buf = append(buf, kv[0]...)
		buf = append(buf, ": "...)
		buf = append(buf, kv[1]...)
		buf = append(buf, "\r\n"...)
	}
	buf = append(buf, "\r\n"...)
	buf = append(buf, body...)
	_, err := w.Write(buf)
	return err
}

// newSessionToken mints an unguessable session cookie.
func newSessionToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// ipv4Dst and ipv4Src extract addresses from an IPv4 packet.
func ipv4Dst(pkt []byte) net.IP {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil
	}
	return net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])
}

func ipv4Src(pkt []byte) net.IP {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil
	}
	return net.IPv4(pkt[12], pkt[13], pkt[14], pkt[15])
}

// offerDTLS mints an App-ID for this client, arms the listener to expect a UDP
// flow presenting it, and adds the DTLS headers to the CONNECT reply.
//
// The key is derived from this TLS session with an RFC 5705 exporter, so the UDP
// channel inherits the authentication the client has already completed and no
// second credential exchange is needed. When the exporter is unavailable — a TLS
// 1.2 session without Extended Master Secret, which Go rightly refuses to export
// from — DTLS is simply not offered.
func (s *Server) offerDTLS(conn net.Conn, hdr *headerList, c *serverClient, mtu int) error {
	psk, err := dtlsPSK(conn)
	if err != nil {
		return err
	}
	appID := make([]byte, dtlsAppIDLen)
	if _, err := rand.Read(appID); err != nil {
		return fmt.Errorf("anyconnect: App-ID: %w", err)
	}
	c.appID = string(appID)

	s.dtls.expect(c.appID, &pendingSession{
		psk:    psk,
		mtu:    mtu,
		accept: func(dc *dtls.Conn) { c.attachDTLS(dc) },
	})

	port := s.cfg.DTLSConn.LocalAddr().(*net.UDPAddr).Port
	hdr.set(hdrDTLSCipherSuite, pskNegotiate)
	hdr.set(hdrDTLSAppID, hex.EncodeToString(appID))
	hdr.setInt(hdrDTLSPort, port)
	hdr.setInt(hdrDTLSMTU, mtu)
	hdr.setInt(hdrDTLSDPD, serverDPD)
	hdr.setInt(hdrDTLSKeepalive, serverKeepalive)
	return nil
}

// dtlsAppIDLen is the length of the identifier tying a UDP flow to the HTTPS
// session that authorised it. It is random and single-use, so it only has to be
// unguessable, not structured.
const dtlsAppIDLen = 32

// attachDTLS adopts a completed DTLS channel for this client and begins reading
// it. Data then leaves over UDP; the TLS connection stays open for control.
func (c *serverClient) attachDTLS(dc *dtls.Conn) {
	ch := &dtlsChannel{conn: dc}
	ch.up.Store(true)
	c.dtls.Store(ch)
	c.srv.logger.Printf("anyconnect: DTLS channel up for %s (%s)", c.username, dc.RemoteAddr())
	go c.dtlsReadLoop(ch)
}

// dtlsReadLoop delivers this client's UDP traffic. Losing the channel demotes it
// to TLS rather than ending the session.
func (c *serverClient) dtlsReadLoop(ch *dtlsChannel) {
	buf := make([]byte, maxPayload)
	for {
		n, err := ch.conn.Read(buf)
		if err != nil {
			if ch.up.Swap(false) {
				c.srv.logger.Printf("anyconnect: DTLS channel for %s lost, falling back to TLS: %v", c.username, err)
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
			// Same source check as the TLS path: a client may only inject traffic
			// from the address it was assigned.
			if src := ipv4Src(payload); src == nil || !src.Equal(c.innerIP) {
				continue
			}
			if inner := dataplane.TrimToIP(payload); inner != nil {
				_, _ = c.srv.tun.Write(inner)
			}
		case typeDPDReq:
			_ = ch.send(typeDPDResp, payload)
		}
	}
}
