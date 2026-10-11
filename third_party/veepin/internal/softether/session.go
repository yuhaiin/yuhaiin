package softether

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/xen0bit/veepin/dataplane"
)

// SoftEther VPN native protocol session: TLS connection, PACK-based control
// exchange, and Ethernet frame forwarding.

// ErrAuth reports a login the server refused. It covers the "error" element the
// reference sets on a rejected login and a welcome that never arrived: both
// mean the credentials did not get a session, and neither is a transport fault
// the caller should sit and retry.
//
// The distinction is not cosmetic here. SoftEther's server counts failed logins
// per account and locks out, so `veepin connect -retry` reconnecting through a
// wrong password is the one case where retrying makes the outcome worse rather
// than merely wasting time.
var ErrAuth = errors.New("softether: authentication failed")

// Protocol constants matching SoftEther's definitions.
const (
	DefaultPort = 443

	// CLIENT_AUTHTYPE_PASSWORD, Cedar.h. The server switches on this to decide
	// which credential it is being offered.
	clientAuthTypePassword = 1

	// CONNECTION_TCP, Cedar.h. The only transport this implements; the UDP
	// acceleration path is not offered.
	connectionTCP = 0

	// The version and build this implementation reports, and the version and
	// build a SoftEther peer must find acceptable. Real builds report their
	// own; these are the smallest values the reference accepts without
	// treating the peer as an ancient client needing compatibility shims.
	protocolVersion = 400
	protocolBuild   = 9799

	// The identification strings each role sends. Named after the reference's
	// ServerStr/ClientStr, and deliberately honest about what is on the other
	// end rather than impersonating a SoftEther build -- a server operator
	// reading a session list should see what actually connected.
	serverStr = "veepin SoftEther-compatible Server"
	clientStr = "veepin SoftEther-compatible Client"

	// SESSION timeout advertised in the welcome PACK, in milliseconds.
	sessionTimeoutMillis = 30000
)

// ServerSession holds state for one connected SoftEther client.
type ServerSession struct {
	conn   *tls.Conn
	br     *bufio.Reader
	srv    *Server
	bridge *Bridge
	port   PortID
	mu     sync.Mutex

	// Client authentication state. Atomic because forwardTo reads it from a
	// *peer's* frame-loop goroutine while this session's own goroutine sets it.
	authenticated atomic.Bool
	username      string
	hubName       string
	assignedIP    net.IP

	// Random challenge sent in the hello response.
	random [sha0Size]byte

	// Session key, handed to the client in the welcome PACK. SoftEther uses
	// it to bind additional connections to an existing session; this
	// implementation accepts one connection per session, so it is generated,
	// sent, and never consulted again. It is still random per session rather
	// than a constant: a client that reconnects and is handed the same key
	// would let a passive observer tie two sessions together.
	sessionKey   [sha0Size]byte
	sessionKey32 uint32

	logf func(format string, args ...interface{})
}

// CredentialLookup returns the password for a username, and whether the user
// exists. A nil lookup rejects every login: a VPN server that authenticates
// nobody must refuse everybody, not admit everybody.
type CredentialLookup func(username string) (password string, ok bool)

// Server handles incoming SoftEther VPN connections.
type Server struct {
	config      *tls.Config
	bridge      *Bridge
	gatewayMAC  MACAddr
	gatewayIP   net.IP
	credentials CredentialLookup
	logf        func(format string, args ...interface{})
	shutdown    atomic.Bool

	// sessions maps a bridge port to the session that owns it, so a frame the
	// bridge resolves to a port can actually be written to that peer. Without
	// it the switch learns addresses and forwards nothing.
	sessionsMu sync.RWMutex
	sessions   map[PortID]*ServerSession

	// assigned tracks which addresses are out, so two clients are not handed
	// the same one. SoftEther itself assigns no address -- the segment is
	// layer 2 and addressing inside it comes from DHCP or static
	// configuration -- so this exists only for veepin's own client, which asks
	// for one. It is a sequential allocator over the gateway's /24 rather than
	// anything cleverer because the alternative it replaces was the constant
	// 10.70.0.2 for every client on the switch.
	assignedMu sync.Mutex
	assigned   map[PortID]net.IP

	// shaper pads outbound frames so an inner flow's size pattern does not
	// survive encapsulation, and shapeMTU is the frame-level target. Nil means
	// no shaping, which is the default -- see doc/traffic-shaping.md.
	shaper   *dataplane.Shaper
	shapeMTU int

	// local is the server's own interface as a switch port (local.go), or nil
	// when nothing is attached. Guarded separately from sessions because
	// deliver consults both, and one lock over two unrelated maps is how a
	// deadlock gets written later.
	localMu sync.RWMutex
	local   *localPort
}

// NewServer creates a SoftEther VPN server. creds authenticates logins; passing
// nil makes every login fail.
func NewServer(tlsCfg *tls.Config, bridge *Bridge, gatewayMAC MACAddr, gatewayIP net.IP, creds CredentialLookup) *Server {
	return &Server{
		config:      tlsCfg,
		bridge:      bridge,
		gatewayMAC:  gatewayMAC,
		gatewayIP:   gatewayIP,
		credentials: creds,
		sessions:    make(map[PortID]*ServerSession),
		assigned:    make(map[PortID]net.IP),
		logf:        func(string, ...interface{}) {},
	}
}

// addSession / removeSession / sessionFor keep the port-to-session registry.
func (s *Server) addSession(ss *ServerSession) {
	s.sessionsMu.Lock()
	s.sessions[ss.port] = ss
	s.sessionsMu.Unlock()
}

func (s *Server) removeSession(p PortID) {
	s.sessionsMu.Lock()
	delete(s.sessions, p)
	s.sessionsMu.Unlock()
}

func (s *Server) sessionFor(p PortID) *ServerSession {
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()
	return s.sessions[p]
}

// assignAddress hands out the next free address in the gateway's /24,
// skipping the gateway itself. It returns nil when the pool is exhausted,
// which the caller reports rather than papering over -- an address collision
// between two clients on one layer-2 segment is worse than a refused login,
// because it presents as intermittent packet loss for both of them.
func (s *Server) assignAddress(port PortID) net.IP {
	s.assignedMu.Lock()
	defer s.assignedMu.Unlock()

	if ip, ok := s.assigned[port]; ok {
		return ip
	}

	base := s.gatewayIP.To4()
	if base == nil {
		return nil
	}
	taken := make(map[string]bool, len(s.assigned))
	for _, ip := range s.assigned {
		taken[ip.String()] = true
	}

	// .1 is conventionally the gateway and .255 is broadcast; start at .2.
	for host := byte(2); host < 255; host++ {
		candidate := net.IPv4(base[0], base[1], base[2], host)
		if candidate.Equal(s.gatewayIP) || taken[candidate.String()] {
			continue
		}
		s.assigned[port] = candidate
		return candidate
	}
	return nil
}

// releaseAddress returns a port's address to the pool.
func (s *Server) releaseAddress(port PortID) {
	s.assignedMu.Lock()
	delete(s.assigned, port)
	s.assignedMu.Unlock()
}

// SingleUser is a CredentialLookup for the one-account case the CLI exposes.
func SingleUser(username, password string) CredentialLookup {
	return func(u string) (string, bool) {
		if u != username {
			return "", false
		}
		return password, true
	}
}

// SetLogger sets the server's log function.
func (s *Server) SetLogger(f func(string, ...interface{})) {
	if f != nil {
		s.logf = f
	}
}

// Serve accepts connections on the TLS listener.
func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.shutdown.Load() {
				return nil
			}
			return fmt.Errorf("softether: accept: %w", err)
		}
		go s.handleConn(conn)
	}
}

// Close shuts down the server.
func (s *Server) Close() { s.shutdown.Store(true) }

func (s *Server) handleConn(raw net.Conn) {
	tlsConn, ok := raw.(*tls.Conn)
	if !ok {
		raw.Close()
		return
	}
	if err := tlsConn.Handshake(); err != nil {
		s.logf("softether: TLS handshake: %v", err)
		tlsConn.Close()
		return
	}

	port := s.bridge.NewPort()
	ss := &ServerSession{
		conn:   tlsConn,
		br:     bufio.NewReader(tlsConn),
		srv:    s,
		bridge: s.bridge,
		port:   port,
		logf:   s.logf,
	}
	// Generate the challenge the client's password digest is bound to. A
	// predictable value here would make every login replayable.
	if _, err := rand.Read(ss.random[:]); err != nil {
		s.logf("softether: challenge generation failed: %v", err)
		tlsConn.Close()
		return
	}
	if _, err := rand.Read(ss.sessionKey[:]); err != nil {
		s.logf("softether: session key generation failed: %v", err)
		tlsConn.Close()
		return
	}
	ss.sessionKey32 = binary.BigEndian.Uint32(ss.sessionKey[:4])

	s.logf("softether: new connection from %s (port %d)", tlsConn.RemoteAddr(), port)

	s.addSession(ss)
	// exchange returns only when the session is over, and it always returns an
	// error: the frame loop's sole exit is a failed read, so even an orderly
	// client disconnect arrives here as io.EOF. Logging it unconditionally is
	// what the `err != nil` check did anyway -- the check was never false.
	s.logf("softether: session %d: %v", port, ss.exchange())

	s.removeSession(port)
	s.releaseAddress(port)
	s.bridge.RemovePort(port)
	tlsConn.Close()
}

// exchange runs the full control exchange and then forwards frames until the
// session ends. It never returns nil -- frameLoop loops until a read fails, so
// the return value says how the session ended rather than whether it succeeded.
func (ss *ServerSession) exchange() error {
	// Phase 0: the HTTP signature. A SoftEther connection opens with an HTTP
	// POST, not with a PACK -- see http.go. Anything that reaches this
	// listener without it is a web client, a scanner, or a veepin from before
	// this layer existed.
	if err := readSignature(ss.br, ss.conn); err != nil {
		return err
	}

	// Phase 1: Hello exchange.
	if err := ss.helloExchange(); err != nil {
		return err
	}

	// Phase 2: Authentication.
	authResult, err := ss.authenticate()
	if err != nil {
		return err
	}
	if !authResult {
		return fmt.Errorf("authentication failed for %q", ss.username)
	}

	ss.authenticated.Store(true)
	ss.logf("softether: session %d authenticated as %q", ss.port, ss.username)

	// Phase 3: Frame forwarding loop.
	return ss.frameLoop()
}

// helloExchange sends the server hello. There is no client hello to read: the
// signature POST is the client's opening move, and ServerUploadHello answers
// it directly. This package used to wait for a PACK{method=hello} that no
// SoftEther client has ever sent, which is a deadlock against a real peer and
// invisible against another veepin that dutifully sent one.
//
// The field names are GetHello's: "hello" carries the server's version string,
// and the challenge is "random". Not "method", and not "ver".
func (ss *ServerSession) helloExchange() error {
	resp := NewPack()
	resp.Add("hello", TypeStr, StrValue(serverStr))
	resp.Add("version", TypeInt, IntValue(protocolVersion))
	resp.Add("build", TypeInt, IntValue(protocolBuild))
	resp.Add("random", TypeData, DataValue(ss.random[:]))

	return ss.writePack(resp)
}

func (ss *ServerSession) authenticate() (bool, error) {
	req, err := ss.readPack()
	if err != nil {
		return false, fmt.Errorf("auth read: %w", err)
	}

	// Expect login with password authentication.
	method := req.GetStr("method")
	if method != "login" {
		return false, fmt.Errorf("expected login, got %q", method)
	}

	ss.username = req.GetStr("username")
	ss.hubName = req.GetStr("hubname")
	securePassword := req.GetData("secure_password")
	if len(securePassword) != 20 {
		return false, fmt.Errorf("bad secure_password length %d", len(securePassword))
	}

	// Verify the challenge response: the client sent
	// SHA0(SHA0(password+UPPER(username)) || random), and only someone who
	// knows the password can produce it for our random. See auth.go for why
	// each of those three things is not what it looks like. Comparing in
	// constant time keeps the reply from leaking how much of the digest
	// matched.
	if !ss.verifySecurePassword(securePassword) {
		ss.logf("softether: login rejected for %q", ss.username)
		resp := NewPack()
		resp.Add("method", TypeStr, StrValue("login"))
		resp.Add("error", TypeInt, IntValue(1))
		_ = ss.writePack(resp)
		return false, nil
	}
	ss.assignedIP = ss.srv.assignAddress(ss.port)

	// The welcome PACK. PackWelcome in the reference carries a great deal more
	// than this -- UDP acceleration keys, R-UDP bulk keys, an Azure relay
	// address -- all of it for features this implementation does not offer.
	// What is here is the subset a client needs to bring a session up: its
	// name, the session key, and the connection parameters it will not
	// negotiate again.
	//
	// use_encrypt is 1 because the session is inside TLS. use_compress is 0
	// and should stay 0: SoftEther's compression is zlib over
	// attacker-influenced plaintext inside TLS, which is the CRIME/BREACH
	// shape, and doc/security.md says so.
	resp := NewPack()
	resp.Add("session_name", TypeStr, StrValue(fmt.Sprintf("SID-%s-%d", asciiUpper(ss.username), ss.port)))
	resp.Add("connection_name", TypeStr, StrValue("CID-"+serverStr))
	resp.Add("max_connection", TypeInt, IntValue(1))
	resp.Add("use_encrypt", TypeInt, IntValue(1))
	resp.Add("use_compress", TypeInt, IntValue(0))
	resp.Add("half_connection", TypeInt, IntValue(0))
	resp.Add("timeout", TypeInt, IntValue(sessionTimeoutMillis))
	resp.Add("qos", TypeInt, IntValue(0))
	resp.Add("session_key", TypeData, DataValue(ss.sessionKey[:]))
	resp.Add("session_key_32", TypeInt, IntValue(ss.sessionKey32))
	// The session policy, as PackAddPolicy writes it. See policy.go for why it
	// is sent even though a welcome without it parses: an omitted flag gives
	// the peer the value we wanted by accident rather than by statement.
	addPolicy(resp, defaultPolicy(1))
	resp.Add("vlan_id", TypeInt, IntValue(0))

	if err := ss.writePack(resp); err != nil {
		return false, err
	}
	return true, nil
}

// verifySecurePassword recomputes the client's challenge response from the
// stored password and compares it against what arrived.
func (ss *ServerSession) verifySecurePassword(got []byte) bool {
	if ss.srv == nil || ss.srv.credentials == nil {
		return false
	}
	password, ok := ss.srv.credentials(ss.username)
	if !ok {
		// Still run the hash so a missing user and a wrong password take the
		// same time; otherwise the server enumerates its own accounts.
		password = ""
	}
	want := securePassword(hashPassword(ss.username, password), ss.random)
	return ok && subtle.ConstantTimeCompare(want[:], got) == 1
}

func (ss *ServerSession) frameLoop() error {
	r := newBlockReader(ss.br)
	for {
		raw, err := r.next()
		if err != nil {
			return fmt.Errorf("frame read: %w", err)
		}

		frame, ok := ParseFrame(raw)
		if !ok {
			continue
		}

		// A nil Destinations means flood (broadcast, multicast, or a destination
		// the bridge has not learned yet), which is standard switch behaviour.
		result := ss.bridge.Forward(frame, ss.port)
		dests := result.Destinations
		if dests == nil {
			dests = ss.bridge.FloodPorts(ss.port)
		}
		ss.forwardTo(dests, raw)
	}
}

// forwardTo writes one frame to every destination port that still has a live
// session. A write failure is the peer's problem, not this session's: the
// sender must not be torn down because a different client went away.
func (ss *ServerSession) forwardTo(dests []PortID, frame []byte) {
	if ss.srv == nil {
		return
	}
	ss.srv.deliver(dests, frame, ss.port)
}

// writeFrame sends one Ethernet frame as a single-block burst, shaped if the
// server is shaping.
func (ss *ServerSession) writeFrame(frame []byte) error {
	if ss.srv != nil {
		frame = shapeFrame(frame, ss.srv.shaper, ss.srv.shapeMTU)
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return writeBlocks(ss.conn, [][]byte{frame})
}

// readPack reads one PACK from the connection's next HTTP request.
func (ss *ServerSession) readPack() (*Pack, error) {
	return recvPackHTTP(ss.br, true)
}

// writePack sends a PACK as an HTTP response body.
func (ss *ServerSession) writePack(p *Pack) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return sendPackHTTP(ss.conn, p, true, "")
}

// ClientSession is the SoftEther VPN client side.
type ClientSession struct {
	conn   *tls.Conn
	br     *bufio.Reader
	blocks *blockReader
	host   string // Host: header value, as the reference sends the peer's IP
	bridge *Bridge
	port   PortID
	mu     sync.Mutex

	shaper   *dataplane.Shaper
	shapeMTU int

	serverRandom [sha0Size]byte
	uniqueID     [sha0Size]byte
	assignedIP   net.IP
	hubName      string
	sessionName  string
	// policy is what the server said this session may do, when it said
	// anything. It is reported by Policy and not enforced; see policy.go.
	policy Policy

	logf func(format string, args ...interface{})
}

// Policy reports the session policy the server stated in its welcome. The zero
// value is what a server that stated none leaves behind, which is why Access
// being false is not on its own a reason to conclude anything.
func (cs *ClientSession) Policy() Policy { return cs.policy }

// Connect dials a SoftEther VPN server and performs the control exchange.
func Connect(serverAddr string, tlsCfg *tls.Config, username, password, hubName string) (*ClientSession, error) {
	conn, err := tls.Dial("tcp", serverAddr, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("softether: dial: %w", err)
	}

	bridge := NewBridge(DefaultAgeTime)
	port := bridge.NewPort()

	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		host = serverAddr
	}

	cs := &ClientSession{
		conn:    conn,
		br:      bufio.NewReader(conn),
		host:    host,
		bridge:  bridge,
		port:    port,
		hubName: hubName,
		logf:    func(string, ...interface{}) {},
	}

	// A per-connection unique_id. The reference derives one from the machine
	// so a server can recognise a returning client; a random one per
	// connection is deliberate here, because that recognition is a
	// linkability property a VPN client should not volunteer.
	if _, err := rand.Read(cs.uniqueID[:]); err != nil {
		conn.Close()
		return nil, fmt.Errorf("softether: unique id: %w", err)
	}

	// Phase 0: the signature POST that identifies this as a VPN connection.
	if err := writeSignature(conn, host); err != nil {
		conn.Close()
		return nil, fmt.Errorf("softether: signature: %w", err)
	}

	// Phase 1: Hello.
	if err := cs.hello(); err != nil {
		conn.Close()
		return nil, err
	}

	// Phase 2: Authentication.
	if err := cs.login(username, password); err != nil {
		conn.Close()
		return nil, err
	}

	return cs, nil
}

// hello reads the server's hello, which arrives unprompted as the response to
// the signature POST. The client sends no hello of its own -- ClientUploadAuth2
// goes straight from ClientDownloadHello to the login PACK.
func (cs *ClientSession) hello() error {
	resp, err := cs.readPack()
	if err != nil {
		return fmt.Errorf("hello response: %w", err)
	}
	if resp.GetStr("hello") == "" {
		return fmt.Errorf("softether: no hello in the server's first PACK")
	}

	random := resp.GetData("random")
	if len(random) != sha0Size {
		return fmt.Errorf("softether: server challenge is %d octets, want %d", len(random), sha0Size)
	}
	copy(cs.serverRandom[:], random)
	return nil
}

func (cs *ClientSession) login(username, password string) error {
	securePass := securePassword(hashPassword(username, password), cs.serverRandom)

	// PackLoginWithPassword's field set, in its order. authtype is not
	// optional: the server switches on it to decide which credential to look
	// for, and a login without it is read as anonymous.
	req := NewPack()
	req.Add("method", TypeStr, StrValue("login"))
	req.Add("hubname", TypeStr, StrValue(cs.hubName))
	req.Add("username", TypeStr, StrValue(username))
	req.Add("authtype", TypeInt, IntValue(clientAuthTypePassword))
	req.Add("secure_password", TypeData, DataValue(securePass[:]))
	// The client identification the server logs and rate-limits on.
	// PackAddClientVersion's three fields, and then the same three again under
	// the names the hello half uses -- the reference sends both sets and the
	// server reads from both, so sending one is sending half a login.
	req.Add("client_str", TypeStr, StrValue(clientStr))
	req.Add("client_ver", TypeInt, IntValue(protocolVersion))
	req.Add("client_build", TypeInt, IntValue(protocolBuild))
	req.Add("hello", TypeStr, StrValue(clientStr))
	req.Add("version", TypeInt, IntValue(protocolVersion))
	req.Add("build", TypeInt, IntValue(protocolBuild))
	req.Add("client_id", TypeInt, IntValue(0))
	req.Add("protocol", TypeInt, IntValue(connectionTCP))

	// The session parameters. These are not decoration: the server builds the
	// session from them, and a login that omits max_connection asks for a
	// session with no connections in it -- which is granted, answered with a
	// welcome, and then torn down before a single frame moves. That failure
	// looks exactly like a data-path bug and is a login one.
	req.Add("max_connection", TypeInt, IntValue(1))
	req.Add("use_encrypt", TypeInt, IntValue(1))
	req.Add("use_compress", TypeInt, IntValue(0))
	req.Add("half_connection", TypeInt, IntValue(0))
	req.Add("qos", TypeInt, IntValue(0))
	req.Add("require_bridge_routing_mode", TypeInt, IntValue(0))
	req.Add("require_monitor_mode", TypeInt, IntValue(0))
	req.Add("unique_id", TypeData, DataValue(cs.uniqueID[:]))

	if err := cs.writePack(req); err != nil {
		return err
	}

	resp, err := cs.readPack()
	if err != nil {
		return fmt.Errorf("auth response: %w", err)
	}
	// The reference signals failure with an "error" element and success with a
	// welcome PACK that has no such element. Checking only for error == 0
	// would accept any PACK at all, including one from a peer that answered
	// something else entirely.
	if code := resp.GetInt("error"); code != 0 {
		return fmt.Errorf("%w: server returned error %d", ErrAuth, code)
	}
	if resp.GetStr("session_name") == "" {
		return fmt.Errorf("%w: login answered without a welcome", ErrAuth)
	}

	cs.sessionName = resp.GetStr("session_name")
	// The server's policy, if it sent one. It is recorded rather than enforced:
	// see getPolicy for why Access cannot be acted on, and note that the
	// reference client does not act on it either. Logging a session the server
	// says has no access is still worth doing -- it turns "the tunnel is up and
	// carries nothing" into a line that names the reason.
	if policy, ok := getPolicy(resp); ok {
		cs.policy = policy
		if !policy.Access {
			cs.logf("softether: the server's policy grants this session no access")
		}
	}
	// assigned_ip is this implementation's own extension: SoftEther assigns no
	// address in the protocol, because the segment is layer 2 and addressing
	// comes from DHCP or static configuration inside it. A real server does
	// not send this and the field stays nil, which is correct -- see
	// softether.Dial, which does not depend on it.
	if s := resp.GetStr("assigned_ip"); s != "" {
		cs.assignedIP = net.ParseIP(s)
	}
	return nil
}

// SetShaper turns on downstream flow shaping. mtu is the frame-level target,
// Ethernet header included.
func (s *Server) SetShaper(sh *dataplane.Shaper, mtu int) {
	s.shaper, s.shapeMTU = sh, mtu
}

// SetShaper turns on upstream flow shaping for a client session.
func (cs *ClientSession) SetShaper(sh *dataplane.Shaper, mtu int) {
	cs.shaper, cs.shapeMTU = sh, mtu
}

// WriteFrame sends an Ethernet frame to the server as a single-block burst.
func (cs *ClientSession) WriteFrame(frame []byte) error {
	frame = shapeFrame(frame, cs.shaper, cs.shapeMTU)
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return writeBlocks(cs.conn, [][]byte{frame})
}

// ReadFrame reads the next Ethernet frame from the server.
//
// The returned slice aliases the session's read buffer and is only valid until
// the next call, matching every other inbound parser in the tree.
func (cs *ClientSession) ReadFrame() ([]byte, error) {
	if cs.blocks == nil {
		cs.blocks = newBlockReader(cs.br)
	}
	return cs.blocks.next()
}

// WriteKeepAlive sends a keepalive block. The data path is otherwise silent
// when nothing is flowing, and a SoftEther server times a session out.
func (cs *ClientSession) WriteKeepAlive() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return writeKeepAlive(cs.conn)
}

// Close closes the client session.
func (cs *ClientSession) Close() error {
	return cs.conn.Close()
}

// readPack reads one PACK from the connection's next HTTP response.
func (cs *ClientSession) readPack() (*Pack, error) {
	return recvPackHTTP(cs.br, false)
}

// writePack sends a PACK as the body of an HTTP POST.
func (cs *ClientSession) writePack(p *Pack) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return sendPackHTTP(cs.conn, p, false, cs.host)
}
