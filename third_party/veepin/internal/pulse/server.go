package pulse

// The server engine: an Ivanti Connect Secure gateway.
//
// One TLS listener carries every client's authentication, configuration and —
// unless it took the ESP path — its data. One UDP socket carries the ESP paths.
// One TUN is shared by all of them, with inbound IP routed to the owning client
// by inner destination address.
//
// The TUN is read by a single loop rather than by a dataplane.Pump, because a
// gateway here serves two kinds of client at once: some on ESP, some on the
// IF-T/TLS carrier. Both are reached through one small interface, and the loop
// picks between them by destination.

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/ikev2/esp"
	"github.com/xen0bit/veepin/internal/userdb"
	"github.com/xen0bit/veepin/internal/vlog"
)

// tunIO is the userspace TUN the data path reads IP from and writes IP to.
// *dataplane.TUN satisfies it; tests supply a fake.
type tunIO interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
}

// DefaultESPPort is where a gateway serves the ESP data path unless told
// otherwise. It is the NAT-T port, which is what a Pulse server uses.
const DefaultESPPort = 4500

// ServerConfig configures a gateway.
type ServerConfig struct {
	Users map[string]string // username -> password
	Pool  *dataplane.AddrPool
	// ServerIP is the gateway's own address inside the tunnel.
	ServerIP net.IP
	// PublicIP is the address clients reach this gateway on. Empty means "the
	// address each client's own connection arrived on", which is right unless
	// the gateway is behind a DNAT.
	PublicIP net.IP
	DNS      []net.IP
	Domain   string
	// Routes are the split-tunnel networks pushed to clients. Empty tells them
	// nothing, which they read as "send everything".
	Routes []Route

	// NoESP serves the IF-T/TLS data path only, leaving the UDP port unbound
	// and handing out no keying material.
	NoESP   bool
	ESPPort int

	// Shape is the per-flow downstream shaping budget in bytes; 0 disables it.
	Shape  int
	MTU    int
	Logger *vlog.Logger
}

// clientLink is how the TUN loop reaches one client, whichever data path it
// took. minInner is the size the packet should be padded towards; zero means no
// padding.
type clientLink interface {
	send(pkt []byte, minInner int) error
}

// espPeer is a client on the ESP data path.
type espPeer struct {
	srv  *Server
	sa   *esp.SA
	addr *net.UDPAddr
	mu   sync.Mutex
}

func (p *espPeer) send(pkt []byte, minInner int) error {
	var out []byte
	var err error
	if minInner > len(pkt) {
		out, err = p.sa.EncapsulatePadded(pkt, espNextHeader(pkt), minInner)
	} else {
		out, err = p.sa.Encapsulate(pkt, espNextHeader(pkt))
	}
	if err != nil {
		return err
	}
	p.mu.Lock()
	to := p.addr
	p.mu.Unlock()
	_, err = p.srv.udp().WriteToUDP(out, to)
	return err
}

// noteAddr follows a client whose NAT binding moves.
func (p *espPeer) noteAddr(a *net.UDPAddr) {
	p.mu.Lock()
	if p.addr == nil || p.addr.Port != a.Port || !p.addr.IP.Equal(a.IP) {
		p.addr = a
	}
	p.mu.Unlock()
}

// session is one authenticated client.
type session struct {
	info    LoginInfo
	inner   netip.Addr
	link    *link
	esp     *espPeer
	release sync.Once
}

// Server is a running gateway.
type Server struct {
	cfg    ServerConfig
	tun    tunIO
	logger *vlog.Logger
	gate   *dataplane.Gate
	shaper *dataplane.Shaper

	mu       sync.Mutex
	udpConn  *net.UDPConn
	sessions map[netip.Addr]*session
	bySPI    map[uint32]*espPeer
	ln       net.Listener
	closed   bool

	done      chan struct{}
	closeOnce sync.Once
}

// NewServer validates the configuration and binds the engine to a TUN. It binds
// no socket.
func NewServer(cfg ServerConfig, tun tunIO) (*Server, error) {
	if len(cfg.Users) == 0 {
		return nil, errors.New("pulse: at least one user is required")
	}
	if cfg.Pool == nil {
		return nil, errors.New("pulse: an address pool is required")
	}
	logger := cfg.Logger
	s := &Server{
		cfg:      cfg,
		tun:      tun,
		logger:   logger,
		gate:     dataplane.NewGate(dataplane.AdmissionConfig{}),
		sessions: map[netip.Addr]*session{},
		bySPI:    map[uint32]*espPeer{},
		done:     make(chan struct{}),
	}
	if cfg.Shape > 0 {
		s.shaper = dataplane.NewShaper(dataplane.ShapeConfig{Bytes: cfg.Shape})
		logger.Printf("pulse: downstream shaping on, %d bytes per flow", cfg.Shape)
	}
	return s, nil
}

func (s *Server) udp() *net.UDPConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.udpConn
}

// EnableESP arms the ESP data path on a bound socket. It must be called before
// Serve, so no client is handed keys for a path that is not yet being read.
func (s *Server) EnableESP(conn *net.UDPConn) {
	s.mu.Lock()
	s.udpConn = conn
	s.mu.Unlock()
}

// espPort is where the gateway serves ESP, or 0 when it does not.
func (s *Server) espPort() int {
	if s.cfg.NoESP || s.udp() == nil {
		return 0
	}
	if s.cfg.ESPPort > 0 {
		return s.cfg.ESPPort
	}
	return DefaultESPPort
}

// mtu is the inner size shaping pads towards.
func (s *Server) mtu() int {
	if s.cfg.MTU <= 0 {
		return maxInnerPacket
	}
	return s.cfg.MTU
}

// Serve accepts TLS connections until Close. It blocks.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	s.ln = ln
	s.mu.Unlock()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return nil
			default:
			}
			return err
		}
		if r := s.gate.Admit(conn.RemoteAddr()); r != dataplane.Admitted {
			s.logger.Warnf("pulse: refusing %s: %v", conn.RemoteAddr(), r)
			_ = conn.Close()
			continue
		}
		go s.serveConn(conn)
	}
}

// serveConn runs one client from authentication to teardown.
func (s *Server) serveConn(conn net.Conn) {
	st, info, err := ServerAuth(conn, s.authenticate)
	if err != nil {
		s.logger.Printf("pulse: %s: %v", conn.RemoteAddr(), err)
		_ = conn.Close()
		return
	}

	inner, err := s.cfg.Pool.Allocate()
	if err != nil {
		s.logger.Printf("pulse: %s: address pool: %v", conn.RemoteAddr(), err)
		_ = conn.Close()
		return
	}
	addr, ok := netip.AddrFromSlice(inner.To4())
	if !ok {
		s.cfg.Pool.Release(inner)
		_ = conn.Close()
		return
	}

	sess := &session{info: info, inner: addr}
	sess.link = newLink(conn, s.tun, s.logger)
	sess.link.sourceIs = addr
	sess.link.shutdown = func() { s.release(sess) }

	if err := s.pushConfig(st, sess, inner); err != nil {
		s.logger.Printf("pulse: %s: configuration: %v", conn.RemoteAddr(), err)
		s.cfg.Pool.Release(inner)
		_ = conn.Close()
		return
	}

	s.mu.Lock()
	s.sessions[addr] = sess
	s.mu.Unlock()
	s.logger.Printf("pulse: %s authenticated as %q, assigned %s", conn.RemoteAddr(), info.User, inner)

	sess.link.readLoop()
}

// pushConfig sends the configuration, the ESP keys where the gateway offers
// them, and the end-of-configuration marker, then handles whatever the client
// answers with.
func (s *Server) pushConfig(st *stream, sess *session, inner net.IP) error {
	port := s.espPort()
	cfg := Config{
		Address: inner.To4(),
		Netmask: net.IP(s.cfg.Pool.Network().Mask),
		DNS:     s.cfg.DNS,
		MTU:     s.mtu(),
		Domain:  s.cfg.Domain,
		Gateway: s.cfg.ServerIP,
		Routes:  s.cfg.Routes,
	}

	var serverKeys *Keys
	if port > 0 {
		var err error
		if serverKeys, err = GenerateKeys(EncAES256CBC, HMACSHA256); err != nil {
			return err
		}
		cfg.ESPPort = port
		cfg.ESPEncryption = serverKeys.Encr
		cfg.ESPHMAC = serverKeys.Integrit
		cfg.ESPLifeSecs = 3600
		cfg.ESPReplay = 1
		// How long a client waits for ESP before falling back. It is advice,
		// not a deadline this end enforces.
		cfg.ESPFallback = 15
	}
	if err := st.send(VendorJuniper, TypeConfig, BuildConfig(cfg)); err != nil {
		return err
	}
	if serverKeys != nil {
		pkt, err := BuildESPPacket(serverKeys)
		if err != nil {
			return err
		}
		if err := st.send(VendorJuniper, TypeConfig, pkt); err != nil {
			return err
		}
	}
	if err := st.send(VendorJuniper, TypeConfigDone, make([]byte, 4)); err != nil {
		return err
	}

	// The link takes over the connection from here, and it must not read past
	// what the stream's buffer already holds.
	sess.link.seq = st.seq
	if serverKeys != nil {
		s.awaitESPResponse(st, sess, serverKeys, cfg)
	}
	return nil
}

// awaitESPResponse reads the client's answer to the keying packet, if it sends
// one. A client that does not simply stays on the IF-T/TLS data path, which is
// why nothing here is an error.
func (s *Server) awaitESPResponse(st *stream, sess *session, serverKeys *Keys, cfg Config) {
	for range 2 { // the keying response, then "ncmo=1"
		m, err := st.recv()
		if err != nil {
			return
		}
		if m.Vendor != VendorJuniper {
			continue
		}
		switch m.Type {
		case TypeConfig:
			clientKeys, _, perr := ParseESPPacket(m.Payload, cfg.ESPEncryption, cfg.ESPHMAC)
			if perr != nil {
				s.logger.Printf("pulse: %s: ESP response: %v", sess.info.User, perr)
				return
			}
			// Each block describes the direction its *sender* will be
			// received on. The server's own block is what the client stamps on
			// packets to the server, so it is the server's inbound SA; the
			// client's block is what the server stamps on packets to the
			// client, so it is the server's outbound one. Getting this
			// backwards produces a pair of SAs that still agree with each
			// other, so only a real peer catches it.
			sa, serr := NewSA(clientKeys, serverKeys)
			if serr != nil {
				s.logger.Printf("pulse: %s: ESP keys: %v", sess.info.User, serr)
				return
			}
			peer := &espPeer{srv: s, sa: sa}
			sess.esp = peer
			s.mu.Lock()
			s.bySPI[serverKeys.SPI] = peer
			s.mu.Unlock()
		case TypeControl:
			// "ncmo=1": the client has the keys and ESP may start.
			if sess.esp != nil {
				s.logger.Printf("pulse: ESP path armed for %s", sess.inner)
			}
			return
		}
	}
}

// authenticate checks a username and password. The comparison is constant-time
// with respect to the password (it was a bare ==, which leaked its length), and
// the stored secret may be a bcrypt verifier: this protocol receives the
// password and compares it, so it never needs to hold one.
func (s *Server) authenticate(user, password string) bool {
	want, ok := s.cfg.Users[user]
	return ok && userdb.Verify(want, password)
}

// ServeESP reads the ESP socket until Close. It blocks.
func (s *Server) ServeESP() {
	conn := s.udp()
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

// handleESP opens one inbound ESP packet and writes the inner packet to the
// TUN. The SPI selects the peer; a packet for an SPI nobody owns is dropped.
func (s *Server) handleESP(pkt []byte, from *net.UDPAddr) {
	if len(pkt) < 4 {
		return
	}
	s.mu.Lock()
	peer := s.bySPI[binary.BigEndian.Uint32(pkt[:4])]
	s.mu.Unlock()
	if peer == nil {
		return
	}
	inner, nh, err := peer.sa.Decapsulate(pkt)
	if err != nil {
		return
	}
	// After, never before: the SPI that found this peer is cleartext, so only a
	// packet that opened under its SA says where the client really is. Noting
	// the source first let one forged datagram point the client's ESP at the
	// forger.
	peer.noteAddr(from)
	// The ESP probe is a single zero octet, and the client considers the path
	// live when it gets that same octet back. It is not an IP packet and must
	// not be routed — echoing it is the whole protocol.
	if len(inner) == 1 && inner[0] == 0 {
		if reply, rerr := peer.sa.Encapsulate(inner, nh); rerr == nil {
			_, _ = s.udp().WriteToUDP(reply, from)
		}
		return
	}
	switch nh {
	case 59:
		// A pure filler packet with nothing inside.
		return
	case 4, 41:
		if inner = dataplane.TrimToIP(inner); inner == nil {
			return
		}
	}
	_, _ = s.tun.Write(inner)
}

// RunTUN routes TUN egress to the client owning the inner destination. It
// blocks until Close.
func (s *Server) RunTUN() {
	buf := make([]byte, maxInnerPacket)
	for {
		n, err := s.tun.Read(buf)
		if err != nil {
			return
		}
		pkt := buf[:n]
		dst, ok := destOf(pkt)
		if !ok {
			continue
		}
		s.mu.Lock()
		sess := s.sessions[dst]
		s.mu.Unlock()
		if sess == nil {
			continue
		}
		var l clientLink = sess.link
		if sess.esp != nil {
			l = sess.esp
		}
		_ = l.send(pkt, s.shaper.Target(pkt, s.mtu()))
	}
}

// destOf reads an IP packet's destination address, for either family.
func destOf(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 1 {
		return netip.Addr{}, false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(pkt[16:20])), true
	case 6:
		if len(pkt) < 40 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(pkt[24:40])), true
	}
	return netip.Addr{}, false
}

// release drops a session from every index and returns its address to the pool.
func (s *Server) release(sess *session) {
	sess.release.Do(func() {
		s.mu.Lock()
		delete(s.sessions, sess.inner)
		if sess.esp != nil {
			for spi, p := range s.bySPI {
				if p == sess.esp {
					delete(s.bySPI, spi)
				}
			}
		}
		s.mu.Unlock()
		s.cfg.Pool.Release(net.IP(sess.inner.AsSlice()))
		s.logger.Printf("pulse: %s (%s) disconnected", sess.info.User, sess.inner)
	})
}

// Close stops the gateway.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		ln, udp := s.ln, s.udpConn
		links := make([]*link, 0, len(s.sessions))
		for _, sess := range s.sessions {
			links = append(links, sess.link)
		}
		s.mu.Unlock()

		close(s.done)
		if ln != nil {
			_ = ln.Close()
		}
		if udp != nil {
			_ = udp.Close()
		}
		for _, l := range links {
			l.stop(nil)
		}
	})
	return nil
}

// Sessions is how many clients are connected, for tests and logs.
func (s *Server) Sessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}
