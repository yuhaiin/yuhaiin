package gp

// The server engine: a GlobalProtect gateway.
//
// It is an http.Handler for the control plane, plus two data paths that can be
// live at the same time for different clients — one TLS connection per SSL
// tunnel, and one shared UDP socket carrying ESP for everyone else. Both feed the
// same TUN, so there is one place that reads it (RunTUN) and one routing table
// from inner address to whichever kind of link that client ended up on.
//
// The tunnel endpoint is not served by net/http at all; Serve (listener.go)
// splits it off in front, because the request the reference client sends for it
// is not one net/http will accept.
//
// The keys are minted here. A gateway generates both SPIs and all four ESP keys
// when it answers getconfig, and the client contributes nothing — so a session's
// keying material exists from the moment the configuration is handed out, and
// opening the SSL tunnel for that session throws it away.

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/userdb"
	"github.com/xen0bit/veepin/internal/vlog"
)

// ServerConfig configures a GlobalProtect gateway.
type ServerConfig struct {
	// Users maps a username to its password. A user absent here is rejected.
	Users map[string]string
	// Pool allocates client addresses.
	Pool *dataplane.AddrPool
	// ServerIP is the gateway's own address inside the tunnel — the client's
	// gateway, and what NAT is anchored on.
	ServerIP net.IP
	// PublicIP is the address clients reach this gateway on, advertised as
	// gw-address and used as the ESP activation target. Empty means "use the
	// address the client's own control connection arrived on", which is right
	// whenever the gateway is not behind a DNAT.
	PublicIP net.IP
	// DNS is offered to clients in the configuration.
	DNS    []net.IP
	Domain string
	// NoESP serves the SSL tunnel only: no keying block is issued, so clients do
	// not try the ESP path at all.
	NoESP bool
	// ESPPort is where ESP is served; 0 means DefaultESPPort.
	ESPPort int
	// Logger receives progress messages; nil discards them.
	Logger *vlog.Logger
	// Gate bounds unauthenticated work; nil installs one with the defaults.
	Gate *dataplane.Gate
	// Shape is the per-flow downstream shaping budget in bytes; 0 disables it.
	// MTU is the inner size shaping pads towards.
	Shape int
	MTU   int
}

// defaultTunnelMTU mirrors client.DefaultTunnelMTU, which this engine does not
// import — the registry is the public gp package's business, not the engine's.
const defaultTunnelMTU = 1400

// sessionTTL bounds how long an authenticated session may sit without a data
// path. It is what stops an address being held forever by a client that logged
// in and went away.
const sessionTTL = 5 * time.Minute

// session is one authenticated login: an address reservation plus, until the
// client picks a data path, the keying material that would let it pick ESP.
type session struct {
	user    string
	addr    net.IP
	esp     *ESPConfig
	expires time.Time
	// releaseOnce makes the address return to the pool and the admission slot
	// return to the gate exactly once, whichever of the several ends gets there
	// first.
	releaseOnce sync.Once
}

// clientLink is one client's data path, whichever kind it is. minInner pads the
// inner packet out before it is sent, for traffic shaping; 0 sends it as it is.
type clientLink interface {
	send(pkt []byte, minInner int) error
}

// espPeer is a client on the ESP data path.
type espPeer struct {
	tunnel *Tunnel
	conn   *net.UDPConn
	addr   net.IP // the client's assigned inner address
}

var errNoESPPeer = errors.New("gp: no ESP return address for this client yet")

func (p *espPeer) send(pkt []byte, minInner int) error {
	to := p.tunnel.PeerAddr()
	if to == nil {
		return errNoESPPeer
	}
	var (
		out []byte
		err error
	)
	if minInner > 0 {
		out, err = p.tunnel.EncapsulatePadded(pkt, minInner)
	} else {
		out, err = p.tunnel.Encapsulate(pkt)
	}
	if err != nil {
		return err
	}
	_, err = p.conn.WriteToUDP(out, to)
	return err
}

// Server is a running GlobalProtect gateway.
type Server struct {
	cfg  ServerConfig
	tun  io.ReadWriteCloser
	gate *dataplane.Gate
	log  *vlog.Logger
	// shaper pads outbound packets so the record or datagram carrying them says
	// less about the packet inside (dataplane/shape.go); nil disables shaping.
	// One Shaper is safe to share here precisely because RunTUN is the single
	// goroutine that reads it — the same single-owner rule the pump relies on.
	shaper *dataplane.Shaper

	mu       sync.Mutex
	sessions map[string]*session       // authcookie -> session
	links    map[netip.Addr]clientLink // assigned address -> data path
	bySPI    map[uint32]*espPeer       // inbound SPI -> ESP client
	espConn  *net.UDPConn
	httpSrv  *http.Server
	closed   bool
}

// NewServer builds the gateway around a shared TUN. It does not listen; the
// caller runs Serve over a TLS listener, plus RunTUN and, for the ESP path,
// EnableESP and ServeESP.
func NewServer(cfg ServerConfig, tun io.ReadWriteCloser) (*Server, error) {
	if cfg.Pool == nil {
		return nil, errors.New("gp: no address pool configured")
	}
	if len(cfg.Users) == 0 {
		return nil, errors.New("gp: no users configured")
	}
	logger := cfg.Logger
	gate := cfg.Gate
	if gate == nil {
		gate = dataplane.NewGate(dataplane.AdmissionConfig{})
	}
	if cfg.MTU <= 0 {
		cfg.MTU = defaultTunnelMTU
	}
	var shaper *dataplane.Shaper
	if cfg.Shape > 0 {
		shaper = dataplane.NewShaper(dataplane.ShapeConfig{Bytes: cfg.Shape})
		logger.Printf("gp: downstream shaping on, %d bytes per flow, MTU %d", cfg.Shape, cfg.MTU)
	}
	return &Server{
		cfg:      cfg,
		tun:      tun,
		gate:     gate,
		log:      logger,
		shaper:   shaper,
		sessions: map[string]*session{},
		links:    map[netip.Addr]clientLink{},
		bySPI:    map[uint32]*espPeer{},
	}, nil
}

// ServeHTTP dispatches the GlobalProtect endpoints.
//
// Every response asks for the connection to be closed. That is not politeness:
// the reference client opens the packet tunnel on whatever HTTPS connection it
// already has, and the tunnel request is not one net/http will accept (see
// listener.go, and the header-less request line it describes). A kept-alive
// control connection would therefore carry that request straight into net/http,
// which rejects it with 400 before the split can divert it. Closing after each
// control response forces the tunnel onto a fresh connection, where it is the
// first request and the split sees it.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Connection", "close")
	switch r.URL.Path {
	case PathPrelogin, PathPortalPrelogin:
		s.handlePrelogin(w)
	case PathLogin:
		s.handleLogin(w, r)
	case PathGetConfig:
		s.handleGetConfig(w, r)
	case PathPortalConfig:
		s.handlePortalConfig(w, r)
	case PathHIPCheck:
		// No host-information profile is required, and saying so plainly is what
		// stops a client waiting to be told to submit one.
		writeXML(w, []byte(`<response status="success"><hip-report-needed>no</hip-report-needed></response>`))
	case PathLogout:
		s.handleLogout(w, r)
	default:
		http.NotFound(w, r)
	}
}

// loginDomain is the authentication domain slot of the login response. It must
// be non-empty and not the literal "(null)" — the reference client normalises
// that spelling to empty and then reports the value as missing, which is noise on
// every connection. The value itself is only echoed back on later requests, so a
// gateway with no domain configured names itself.
func (s *Server) loginDomain() string {
	if s.cfg.Domain != "" {
		return s.cfg.Domain
	}
	return "veepin"
}

func (s *Server) handlePrelogin(w http.ResponseWriter) {
	writeXML(w, BuildPreloginResponse("Enter your credentials"))
}

// handleLogin authenticates and issues the session cookie.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	req, ok := s.authenticate(w, r)
	if !ok {
		return
	}
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

	cookie := newAuthCookie()
	s.mu.Lock()
	s.expireSessionsLocked()
	s.sessions[cookie] = &session{
		user:    req.User,
		addr:    addr,
		expires: time.Now().Add(sessionTTL),
	}
	s.mu.Unlock()

	s.log.Printf("gp: %q authenticated, assigned %s", req.User, addr)
	writeXML(w, BuildLoginResponse(LoginInfo{
		AuthCookie:       cookie,
		PersistentCookie: newAuthCookie(),
		Portal:           hostOf(r),
		User:             req.User,
		Domain:           s.loginDomain(),
		PreferredIP:      addr.String(),
	}))
}

// handlePortalConfig serves the portal's policy document: this host, as the one
// gateway. A client that starts at the portal — which the stock clients do — is
// pointed straight back here.
func (s *Server) handlePortalConfig(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authenticate(w, r); !ok {
		return
	}
	host := hostOf(r)
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><policy>`)
	b.WriteString(`<portal-name>veepin</portal-name><gateways><external><list>`)
	b.WriteString(`<entry name="` + host + `"><priority>1</priority><manual>yes</manual>`)
	b.WriteString(`<description>veepin</description></entry>`)
	b.WriteString(`</list></external></gateways></policy>`)
	writeXML(w, []byte(b.String()))
}

// authenticate checks the credentials on a login-shaped form, answering the
// request itself on failure.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (LoginRequest, bool) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	req, err := ParseLoginForm(string(body))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return LoginRequest{}, false
	}
	pass, ok := s.cfg.Users[req.User]
	if !ok || !userdb.Verify(pass, req.Password) {
		s.log.Warnf("gp: login failed for %q", req.User)
		http.Error(w, "Invalid username or password", http.StatusForbidden)
		return LoginRequest{}, false
	}
	return req, true
}

// handleGetConfig hands out the tunnel configuration, minting the ESP keying
// block as it goes. Repeating the request is how a client rekeys, so a second
// call for a live session replaces the keys rather than being refused.
func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	req, err := ParseGetConfigForm(string(body))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	sess := s.sessions[req.AuthCookie]
	if sess != nil {
		sess.expires = time.Now().Add(sessionTTL)
	}
	s.mu.Unlock()
	if sess == nil {
		http.Error(w, "no session", http.StatusForbidden)
		return
	}

	cfg := Config{
		AssignedIP: sess.addr,
		Netmask:    s.cfg.Pool.Network().Mask,
		DNS:        s.cfg.DNS,
		Domain:     s.cfg.Domain,
		MTU:        s.cfg.MTU,
		Lifetime:   int(24 * time.Hour / time.Second),
		Timeout:    int(sessionTTL / time.Second),
		// No access routes: a full tunnel, so the client routes everything here.
	}
	if !s.cfg.NoESP {
		if esp := s.offerESP(sess, req, r); esp != nil {
			cfg.ESP = esp
			cfg.GatewayAddr = s.publicIP(r)
		}
	}
	writeXML(w, BuildConfigXML(cfg))
}

// offerESP mints a keying block for the session and arms the ESP path for it. It
// returns nil when ESP cannot be offered, which leaves the client on the SSL
// tunnel — a working outcome, not an error.
func (s *Server) offerESP(sess *session, req GetConfigRequest, r *http.Request) *ESPConfig {
	s.mu.Lock()
	conn := s.espConn
	s.mu.Unlock()
	if conn == nil {
		return nil // the ESP socket is not bound; do not advertise keys for it
	}
	if s.publicIP(r) == nil {
		s.log.Printf("gp: no reachable gateway address for ESP; offering the SSL tunnel only")
		return nil
	}

	encAlgo, hmacAlgo := SelectESPAlgos(req.EncAlgos, req.HMACAlgos)
	esp, err := GenerateESP(encAlgo, hmacAlgo)
	if err != nil {
		s.log.Printf("gp: generating ESP keys: %v", err)
		return nil
	}
	if port := s.cfg.ESPPort; port != 0 {
		esp.UDPPort = port
	}
	sa, err := esp.NewSA(false)
	if err != nil {
		s.log.Printf("gp: keying the ESP path: %v", err)
		return nil
	}

	peer := &espPeer{
		tunnel: NewTunnel(sa, esp.C2SSPI, nil, nil),
		conn:   conn,
		addr:   sess.addr,
	}
	na := addrKey(sess.addr)

	s.mu.Lock()
	// A second getconfig replaces the previous keying block: the old SPI stops
	// being accepted at the same moment the new one starts.
	if old := sess.esp; old != nil {
		delete(s.bySPI, old.C2SSPI)
	}
	sess.esp = esp
	s.bySPI[esp.C2SSPI] = peer
	// The client is only put on the ESP path here if it is not already on the SSL
	// tunnel; opening that tunnel is what says it chose the other one.
	if _, onSSL := s.links[na].(*tunnelLink); !onSSL {
		s.links[na] = peer
	}
	s.mu.Unlock()
	return esp
}

// serveTunnel turns a diverted connection into the SSL data path. Opening it
// discards the session's ESP keys, which is the protocol's own rule: the two data
// paths are mutually exclusive, and this is the direction the exclusion runs in.
//
// It is called from the listener split rather than from ServeHTTP, because the
// request that gets here is not one net/http will accept — see listener.go. The
// reply is a bare marker, not an HTTP status line, for the same reason.
func (s *Server) serveTunnel(conn net.Conn, reader io.Reader, query string) {
	user, cookie := ParseTunnelRequest(query)
	s.mu.Lock()
	sess := s.sessions[cookie]
	s.mu.Unlock()
	if sess == nil || sess.user != user {
		s.log.Printf("gp: tunnel request with an unknown session")
		// There is no HTTP response shape here that a client understands, and it
		// is looking for exactly twelve bytes; closing is the clearest refusal.
		_ = conn.Close()
		return
	}
	if _, err := conn.Write([]byte(TunnelStart)); err != nil {
		_ = conn.Close()
		return
	}
	s.runSSLLink(conn, reader, sess, cookie)
}

// runSSLLink serves one SSL tunnel until it ends, releasing the session on the
// way out.
func (s *Server) runSSLLink(conn net.Conn, reader io.Reader, sess *session, cookie string) {
	link := newLink(conn, reader, s.tun, s.log)
	link.ownsTUN = false
	link.assignedSrc = sess.addr
	link.answerKeepalives = true

	na := addrKey(sess.addr)
	s.mu.Lock()
	if esp := sess.esp; esp != nil {
		// The SSL tunnel invalidates the keying block this session was given.
		delete(s.bySPI, esp.C2SSPI)
		sess.esp = nil
	}
	s.links[na] = link
	s.mu.Unlock()
	s.log.Printf("gp: tunnel up for %s over TLS", sess.addr)

	go link.readLoop()
	_ = link.Wait()

	s.mu.Lock()
	if s.links[na] == clientLink(link) {
		delete(s.links, na)
	}
	s.mu.Unlock()
	s.release(cookie, sess)
	s.log.Printf("gp: tunnel for %s closed", sess.addr)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	req, err := ParseGetConfigForm(string(body))
	if err == nil && req.AuthCookie != "" {
		s.mu.Lock()
		sess := s.sessions[req.AuthCookie]
		s.mu.Unlock()
		if sess != nil {
			s.teardown(req.AuthCookie, sess)
		}
	}
	writeXML(w, []byte(`<response status="success"/>`))
}

// EnableESP gives the gateway its UDP socket. It must be called before clients
// fetch their configuration, since a gateway with no socket does not offer keys
// for one. The caller runs ServeESP.
func (s *Server) EnableESP(conn *net.UDPConn) {
	s.mu.Lock()
	s.espConn = conn
	s.mu.Unlock()
}

// ServeESP reads the ESP socket until it closes, decapsulating each datagram
// onto the shared TUN. It blocks.
func (s *Server) ServeESP() {
	s.mu.Lock()
	conn := s.espConn
	s.mu.Unlock()
	if conn == nil {
		return
	}
	buf := make([]byte, maxInnerPacket)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		s.handleESP(buf[:n], from)
	}
}

// handleESP processes one inbound ESP datagram.
func (s *Server) handleESP(pkt []byte, from *net.UDPAddr) {
	if len(pkt) < 8 {
		return
	}
	spi := binary.BigEndian.Uint32(pkt[:4])
	s.mu.Lock()
	peer := s.bySPI[spi]
	s.mu.Unlock()
	if peer == nil {
		return
	}
	inner, err := peer.tunnel.Decapsulate(pkt)
	if err != nil {
		return
	}
	// The return address is followed only once the datagram has authenticated,
	// so a forged packet cannot redirect a client's traffic.
	peer.tunnel.SetPeerAddr(from)
	if !sourceIs(inner, peer.addr) {
		// A client sending as someone else is spoofing; drop it rather than let
		// it reach the shared TUN.
		return
	}
	if IsActivationPing(inner) {
		// The activation ping is addressed to the gateway's own outer address,
		// which is not somewhere the tunnel should route traffic. Answering it
		// here is what tells the client the path carries traffic both ways.
		if reply, err := ActivationReply(inner); err == nil {
			if err := peer.send(reply, 0); err != nil {
				s.log.Printf("gp: answering the activation ping for %s: %v", peer.addr, err)
				return
			}
			// Logged on every probe of the burst rather than once, because it is
			// the only positive evidence that the ESP path — not the fallback —
			// is what carries this client, and the interop harness looks for it.
			s.log.Printf("gp: ESP path up for %s", peer.addr)
		}
		return
	}
	if _, err := s.tun.Write(inner); err != nil {
		s.log.Printf("gp: writing to the TUN: %v", err)
	}
}

// RunTUN reads the shared TUN and routes each packet to the client that owns its
// destination, over whichever data path that client is on. It blocks until the
// server closes.
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
		// A non-zero target pads the packet out to it, so what the carrier shows
		// on the wire is the same size whatever the packet was.
		if err := link.send(buf[:n], s.shaper.Target(buf[:n], s.cfg.MTU)); err != nil {
			s.log.Printf("gp: send to %s: %v", dst, err)
		}
	}
}

// Clients reports how many data paths are active, for tests.
func (s *Server) Clients() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.links)
}

// Close stops the gateway: it tears down active links and closes the TUN.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	conn := s.espConn
	httpSrv := s.httpSrv
	links := make([]clientLink, 0, len(s.links))
	for _, l := range s.links {
		links = append(links, l)
	}
	s.mu.Unlock()

	if httpSrv != nil {
		_ = httpSrv.Close()
	}
	if conn != nil {
		_ = conn.Close()
	}
	for _, l := range links {
		if tl, ok := l.(*tunnelLink); ok {
			_ = tl.Close()
		}
	}
	if s.tun != nil {
		return s.tun.Close()
	}
	return nil
}

// teardown ends a session and everything hanging off it.
func (s *Server) teardown(cookie string, sess *session) {
	na := addrKey(sess.addr)
	s.mu.Lock()
	link := s.links[na]
	delete(s.links, na)
	if sess.esp != nil {
		delete(s.bySPI, sess.esp.C2SSPI)
		sess.esp = nil
	}
	s.mu.Unlock()

	if tl, ok := link.(*tunnelLink); ok {
		// Closing the link makes its own goroutine release the session; doing it
		// here as well is harmless, because releasing is once-only.
		_ = tl.Close()
	}
	s.release(cookie, sess)
}

// release returns the session's address and admission slot, exactly once.
func (s *Server) release(cookie string, sess *session) {
	sess.releaseOnce.Do(func() {
		s.mu.Lock()
		if s.sessions[cookie] == sess {
			delete(s.sessions, cookie)
		}
		if sess.esp != nil {
			delete(s.bySPI, sess.esp.C2SSPI)
		}
		s.mu.Unlock()
		s.cfg.Pool.Release(sess.addr)
		s.gate.Done()
	})
}

// expireSessionsLocked drops sessions that never took a data path. The caller
// holds mu. A session with a live link is never expired: its link keeps it, and
// the link's own end releases it.
func (s *Server) expireSessionsLocked() {
	now := time.Now()
	for cookie, sess := range s.sessions {
		if now.Before(sess.expires) {
			continue
		}
		if _, live := s.links[addrKey(sess.addr)]; live {
			continue
		}
		expired := sess
		delete(s.sessions, cookie)
		if expired.esp != nil {
			delete(s.bySPI, expired.esp.C2SSPI)
		}
		// Released outside the lock would be tidier, but Release and Done take no
		// lock of ours, so this is safe and keeps the sweep in one place.
		expired.releaseOnce.Do(func() {
			s.cfg.Pool.Release(expired.addr)
			s.gate.Done()
		})
	}
}

// publicIP is the address clients reach this gateway on: the configured one, or
// the local address of the client's own control connection, which is right
// whenever the gateway is not behind a DNAT.
func (s *Server) publicIP(r *http.Request) net.IP {
	if s.cfg.PublicIP != nil {
		return s.cfg.PublicIP
	}
	if local, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		if host, _, err := net.SplitHostPort(local.String()); err == nil {
			if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
				return ip.To4()
			}
		}
	}
	return nil
}

func writeXML(w http.ResponseWriter, doc []byte) {
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write(doc)
}

// hostOf is the name the client used to reach this gateway, without its port.
func hostOf(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.Host); err == nil {
		return host
	}
	return r.Host
}

func remoteAddr(r *http.Request) *net.UDPAddr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return &net.UDPAddr{IP: net.ParseIP(host)}
}

// newAuthCookie mints the 32 hex digits the protocol's cookies are made of.
func newAuthCookie() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// addrKey is the routing table's key for an assigned address.
func addrKey(ip net.IP) netip.Addr {
	a, _ := netip.AddrFromSlice(ip)
	return a.Unmap()
}

// destAddr returns the destination address of an inner IP packet.
func destAddr(pkt []byte) (netip.Addr, bool) {
	if len(pkt) == 0 {
		return netip.Addr{}, false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}), true
	case 6:
		if len(pkt) < 40 {
			return netip.Addr{}, false
		}
		a, ok := netip.AddrFromSlice(pkt[24:40])
		return a, ok
	default:
		return netip.Addr{}, false
	}
}
