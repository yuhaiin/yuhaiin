package fortinet

// The server engine: an HTTPS handler that authenticates, hands out a config,
// and turns the tunnel request into a framed PPP link.
//
// It is an http.Handler so the TLS, request routing and cookies are the standard
// library's; the one unusual move is the tunnel endpoint, which hijacks the
// connection and speaks framed PPP over it with no HTTP response, as the protocol
// requires. One QUIC-free, connection-per-client shape: each tunnel is one PPP
// server session on a NoAuth link, registered under its assigned inner address so
// the shared TUN's read loop can route a packet to the right client.

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/mschap"
	"github.com/xen0bit/veepin/internal/otp"
	"github.com/xen0bit/veepin/internal/ppp"
	"github.com/xen0bit/veepin/internal/udpmux"
	"github.com/xen0bit/veepin/internal/userdb"
	"github.com/xen0bit/veepin/internal/vlog"
)

// ServerConfig configures a Fortinet SSL VPN server.
type ServerConfig struct {
	// Users maps a username to its password. A user absent here is rejected.
	Users map[string]string
	// Pool allocates client addresses.
	Pool *dataplane.AddrPool
	// ServerIP is the server's own inner address (the client's gateway).
	ServerIP net.IP
	// DNS is offered to clients in the config XML.
	DNS []net.IP
	// Logger receives progress messages; nil discards them.
	Logger *vlog.Logger
	// Gate bounds unauthenticated work; nil installs one with the defaults.
	Gate *dataplane.Gate
	// Certificate is the gateway's certificate and key for the DTLS data
	// channel. Without it ServeDTLS refuses to run and the server is TLS-only.
	Certificate *tls.Certificate
	// TOTPSecrets maps a username to its base32 TOTP shared secret. A user
	// listed here must pass a second factor: the password gets them a challenge
	// rather than a cookie. Users absent from this map log in with one factor.
	TOTPSecrets map[string]string
	// TOTP parameters the second factor. The zero value is what authenticator
	// apps assume: SHA1, 6 digits, a 30-second step, one step of drift allowed.
	TOTP otp.Config
	// Shape is the per-flow downstream shaping budget in bytes; 0 disables it.
	// See dataplane/shape.go. MTU is the inner size shaping pads towards, and
	// defaults to defaultTunnelMTU.
	Shape int
	MTU   int
}

// defaultTunnelMTU mirrors client.DefaultTunnelMTU, which this engine does not
// import — the registry is the public fortinet package's business, not the
// engine's. It is only the size shaping pads towards, so a caller reporting a
// different MTU to its clients should set ServerConfig.MTU to match; the public
// package does.
const defaultTunnelMTU = 1400

// Server is a running Fortinet SSL VPN server. It satisfies http.Handler for the
// control and tunnel endpoints, and RunTUN drives the shared TUN's egress.
type Server struct {
	cfg  ServerConfig
	tun  io.ReadWriteCloser
	gate *dataplane.Gate
	log  *vlog.Logger
	// shaper pads outbound PPP frames so the TLS record carrying them says less
	// about the packet inside (dataplane/shape.go); nil disables shaping.
	//
	// One Shaper is safe to share here precisely because RunTUN is the single
	// goroutine that reads it — the same single-owner rule the pump relies on.
	// It would not be safe hung off each pppLink, which is why it lives here.
	shaper *dataplane.Shaper

	mu         sync.Mutex
	dtls       *udpmux.Mux                // the UDP data channel, once ServeDTLS runs
	pending2FA map[string]*challengeState // reqid -> a login awaiting its second factor
	pending    map[string]net.IP          // cookie -> assigned address, between login and tunnel
	links      map[netip.Addr]*pppLink    // assigned address -> active tunnel
	byCookie   map[string]*pppLink        // cookie -> active tunnel, so a later DTLS
	//                                 session can attach to the link it belongs to
	closed   bool
	closedCh chan struct{}
}

// NewServer builds the server around a shared TUN. It does not listen; the
// caller runs an http.Server with the Server as its Handler, plus RunTUN.
func NewServer(cfg ServerConfig, tun io.ReadWriteCloser) (*Server, error) {
	if cfg.Pool == nil {
		return nil, errors.New("fortinet: no address pool configured")
	}
	if len(cfg.Users) == 0 {
		return nil, errors.New("fortinet: no users configured")
	}
	logger := cfg.Logger
	gate := cfg.Gate
	if gate == nil {
		gate = dataplane.NewGate(dataplane.AdmissionConfig{})
	}
	var shaper *dataplane.Shaper
	if cfg.Shape > 0 {
		if cfg.MTU <= 0 {
			cfg.MTU = defaultTunnelMTU
		}
		shaper = dataplane.NewShaper(dataplane.ShapeConfig{Bytes: cfg.Shape})
		logger.Printf("fortinet: downstream shaping on, %d bytes per flow, MTU %d", cfg.Shape, cfg.MTU)
	}
	return &Server{
		cfg:        cfg,
		tun:        tun,
		gate:       gate,
		log:        logger,
		shaper:     shaper,
		pending:    map[string]net.IP{},
		pending2FA: map[string]*challengeState{},
		links:      map[netip.Addr]*pppLink{},
		byCookie:   map[string]*pppLink{},
		closedCh:   make(chan struct{}),
	}, nil
}

// ServeHTTP dispatches the Fortinet endpoints.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case PathLoginCheck:
		s.handleLogin(w, r)
	case PathConfigXML:
		s.handleConfig(w, r)
	case PathTunnel:
		s.handleTunnel(w, r)
	case "/", "/remote/login":
		// A real client's first request is a GET for the login page. It builds
		// its own credential form and POSTs to logincheck regardless of the body,
		// so a minimal 200 with no JavaScript redirect is all it needs to proceed.
		s.handleLoginPage(w)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleLoginPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html")
	_, _ = io.WriteString(w, `<html><body><form action="`+PathLoginCheck+`" method="post">`+
		`<input name="username"><input name="credential" type="password"></form></body></html>`)
}

// challengeState is a login that passed its password and is waiting for a second
// factor. It is deliberately short-lived: it holds no address reservation, so an
// abandoned challenge costs a map entry until it expires.
type challengeState struct {
	username string
	expires  time.Time
}

// challengeTTL bounds how long a second factor may be outstanding. It is
// generous enough to fetch a phone and short enough that a captured reqid is
// worth little.
const challengeTTL = 3 * time.Minute

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))

	// One endpoint serves both stages, as FortiOS does; the body says which.
	if IsChallengeForm(string(body)) {
		s.handleChallenge(w, r, string(body))
		return
	}

	req, err := ParseLoginForm(string(body))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	pass, ok := s.cfg.Users[req.Username]
	if !ok || !userdb.Verify(pass, req.Password) {
		s.log.Warnf("fortinet: login failed for %q", req.Username)
		// FortiOS answers a bad login with ret=1 on a permit-all portal or an
		// error page otherwise; a plain 403 is unambiguous and is what a client
		// treats as auth failure.
		http.Error(w, "ret=4", http.StatusForbidden)
		return
	}

	// A user with a second factor gets a challenge, not a session. No address is
	// reserved and no admission is taken yet: the login is not finished, and a
	// half-finished one must not be able to exhaust either.
	if _, needs2FA := s.cfg.TOTPSecrets[req.Username]; needs2FA {
		s.issueChallenge(w, req.Username)
		return
	}

	s.grantSession(w, r, req.Username)
}

// issueChallenge answers a correct password with a second-factor prompt.
func (s *Server) issueChallenge(w http.ResponseWriter, username string) {
	reqid := newCookie()
	s.mu.Lock()
	s.expireChallengesLocked()
	s.pending2FA[reqid] = &challengeState{username: username, expires: time.Now().Add(challengeTTL)}
	s.mu.Unlock()

	s.log.Printf("fortinet: %q passed its password, awaiting a second factor", username)
	_, _ = io.WriteString(w, BuildChallengeResponse("Enter your token code",
		map[string]string{"reqid": reqid, "polid": "1", "grp": "sslvpn", "magic": reqid}))
}

// handleChallenge verifies the second factor and, on success, issues the session
// the password alone did not earn.
func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request, body string) {
	req, err := ParseChallengeForm(body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	s.expireChallengesLocked()
	state, ok := s.pending2FA[req.Echo["reqid"]]
	if ok {
		// A challenge is single-use whatever the outcome, so a captured reqid
		// cannot be replayed and codes cannot be guessed against it repeatedly.
		delete(s.pending2FA, req.Echo["reqid"])
	}
	s.mu.Unlock()

	if !ok || state.username != req.Username {
		s.log.Warnf("fortinet: challenge response with an unknown or expired reqid")
		http.Error(w, "ret=4", http.StatusForbidden)
		return
	}
	// A push approval is not something this gateway can do -- there is no phone
	// to ask -- so it is refused rather than silently treated as an empty code.
	if req.FTMPush {
		s.log.Printf("fortinet: %q asked for a push approval, which is not offered", req.Username)
		http.Error(w, "ret=4", http.StatusForbidden)
		return
	}

	secret, err := otp.DecodeSecret(s.cfg.TOTPSecrets[state.username])
	if err != nil || !otp.Verify(secret, req.Code, time.Now(), s.cfg.TOTP) {
		s.log.Warnf("fortinet: second factor rejected for %q", state.username)
		http.Error(w, "ret=4", http.StatusForbidden)
		return
	}
	s.log.Printf("fortinet: %q passed its second factor", state.username)
	s.grantSession(w, r, state.username)
}

// expireChallengesLocked drops challenges nobody answered. The caller holds mu.
func (s *Server) expireChallengesLocked() {
	now := time.Now()
	for id, st := range s.pending2FA {
		if now.After(st.expires) {
			delete(s.pending2FA, id)
		}
	}
}

// grantSession completes a login: it takes admission, reserves an address, and
// hands back the cookie that authorises the tunnel.
func (s *Server) grantSession(w http.ResponseWriter, r *http.Request, username string) {
	if s.gate.Admit(remoteAddr(r)) != dataplane.Admitted {
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	addr, err := s.cfg.Pool.Allocate()
	if err != nil {
		s.gate.Done()
		http.Error(w, "no addresses", http.StatusServiceUnavailable)
		return
	}

	cookie := newCookie()
	s.mu.Lock()
	s.pending[cookie] = addr
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: cookie, Path: "/"})
	_, _ = io.WriteString(w, BuildLoginSuccess(PathConfigXML))
	s.log.Printf("fortinet: %q authenticated, assigned %s", username, addr)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	addr, ok := s.cookieAddr(r)
	if !ok {
		http.Error(w, "no session", http.StatusForbidden)
		return
	}
	s.mu.Lock()
	offerDTLS := s.dtls != nil
	s.mu.Unlock()
	cfg := Config{
		AssignedIP: addr,
		DNS:        s.cfg.DNS,
		DTLS:       offerDTLS,
		// No Include routes: a full tunnel, so the client installs a default route.
	}
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write(BuildConfigXML(cfg))
}

func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	addr, ok := s.cookieAddr(r)
	if !ok {
		http.Error(w, "no session", http.StatusForbidden)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "cannot hijack", http.StatusInternalServerError)
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return
	}

	// The session moves from "pending" (holding a pool address) to an active
	// link. Admission was released for it here — its cost is now the connection,
	// not the gate.
	cookie := cookieValueFrom(r)
	s.mu.Lock()
	delete(s.pending, cookie)
	s.mu.Unlock()
	s.gate.Done()

	// The hijacked reader may hold buffered bytes, so it is the read side.
	s.runServerLink(conn, buf.Reader, addr, false, cookie)
}

// runServerLink builds a NoAuth PPP server over conn, registers it under the
// client's inner address, and serves it until it ends -- releasing the address
// on the way out. reader is the read side (nil uses conn); datagram is true for
// the DTLS carrier, where each datagram is one framed record.
func (s *Server) runServerLink(conn net.Conn, reader io.Reader, addr net.IP, datagram bool, cookie string) {
	na, _ := netip.AddrFromSlice(addr.To4())
	na = na.Unmap()

	link := &pppLink{
		conn:        conn,
		reader:      reader,
		tun:         s.tun,
		ownsTUN:     false,
		assignedSrc: addr,
		datagram:    datagram,
		logger:      s.log,
		done:        make(chan struct{}),
	}
	srv := ppp.NewServer(ppp.ServerConfig{
		NoAuth:   true,
		ClientIP: addr,
		ServerIP: s.cfg.ServerIP,
		DNS:      s.cfg.DNS,
	}, link, &serverLinkHandler{})
	link.server = srv

	s.mu.Lock()
	s.links[na] = link
	if cookie != "" {
		s.byCookie[cookie] = link
	}
	s.mu.Unlock()
	carrier := "TLS"
	if datagram {
		carrier = "DTLS"
	}
	s.log.Printf("fortinet: tunnel up for %s over %s", addr, carrier)

	go link.readLoop()
	srv.Start()

	_ = link.Wait()
	s.mu.Lock()
	if s.links[na] == link {
		delete(s.links, na)
	}
	if s.byCookie[cookie] == link {
		delete(s.byCookie, cookie)
	}
	s.mu.Unlock()
	s.cfg.Pool.Release(addr)
	s.log.Printf("fortinet: tunnel for %s (%s) closed", addr, carrier)
}

// RunTUN reads the shared TUN and routes each packet to the client that owns its
// destination. It blocks until the server closes.
func (s *Server) RunTUN() {
	buf := make([]byte, maxInnerPacket)
	for {
		n, err := s.tun.Read(buf)
		if err != nil {
			return
		}
		dst, ok := destAddr(buf[:n])
		if !ok {
			continue
		}
		s.mu.Lock()
		link := s.links[dst]
		s.mu.Unlock()
		if link == nil {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		// A non-zero target pads the PPP Information field out to it, so the TLS
		// record this becomes is the same size whatever the packet was.
		frame := ppp.EncapsulateIPPadded(pkt, s.shaper.Target(pkt, s.cfg.MTU))
		if err := link.SendPPP(frame); err != nil {
			s.log.Printf("fortinet: send to %s: %v", dst, err)
		}
	}
}

// Clients reports how many tunnels are active, for tests.
func (s *Server) Clients() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.links)
}

// Close stops the server: it tears down active links and closes the TUN.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.closedCh)
	mux := s.dtls
	links := make([]*pppLink, 0, len(s.links))
	for _, l := range s.links {
		links = append(links, l)
	}
	s.mu.Unlock()

	if mux != nil {
		_ = mux.Close()
	}
	for _, l := range links {
		_ = l.Close()
	}
	if s.tun != nil {
		return s.tun.Close()
	}
	return nil
}

func (s *Server) cookieAddr(r *http.Request) (net.IP, bool) {
	cookie := cookieValueFrom(r)
	if cookie == "" {
		return nil, false
	}
	s.mu.Lock()
	addr, ok := s.pending[cookie]
	s.mu.Unlock()
	return addr, ok
}

// serverLinkHandler is the PPP server handler. With NoAuth there is nothing to
// do on these events beyond let the link proceed; routing is the TUN loop's job.
type serverLinkHandler struct{}

func (serverLinkHandler) Authenticated(_, _ string, _ [mschap.NTResponseLen]byte) {}
func (serverLinkHandler) NetworkUp()                                              {}
func (serverLinkHandler) Closed(error)                                            {}

func cookieValueFrom(r *http.Request) string {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

func remoteAddr(r *http.Request) *net.UDPAddr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return &net.UDPAddr{IP: net.ParseIP(host)}
}

func newCookie() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// destAddr returns the destination address of an inner IPv4 packet.
func destAddr(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}), true
}
