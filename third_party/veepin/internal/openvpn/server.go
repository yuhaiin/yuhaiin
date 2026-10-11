package openvpn

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/openvpn/control"
	"github.com/xen0bit/veepin/internal/openvpn/data"
	"github.com/xen0bit/veepin/internal/openvpn/keys"
	"github.com/xen0bit/veepin/internal/openvpn/tlswrap"
	"github.com/xen0bit/veepin/internal/openvpn/wire"
	"github.com/xen0bit/veepin/internal/pqpolicy"
	"github.com/xen0bit/veepin/internal/vlog"
)

// ServerConfig configures an OpenVPN responder and its userspace data path. It
// mirrors the client's certificate-authenticated, AES-256-GCM profile: mutual
// TLS against a shared CA, key method 2, and P_DATA_V2 with server-assigned
// peer-ids.
type ServerConfig struct {
	// CA, Cert, Key are PEM: the CA that client certificates must chain to, and
	// the server's own certificate and private key (all required).
	CA   []byte
	Cert []byte
	Key  []byte

	// ListenIP is the local address to bind the UDP socket on; empty binds all.
	ListenIP string
	// ListenPort is the UDP port to accept clients on (default 1194).
	ListenPort int

	// Pool is the internal address pool handed to clients in CIDR form (default
	// 10.8.0.0/24). Its first host is the server's tunnel address.
	Pool string
	// Pool6 is the tunnel's IPv6 prefix in CIDR form, e.g. "fd00:8::/64".
	// Empty, the default, leaves the tunnel IPv4-only.
	//
	// A client's v6 address is *derived* from its v4 one -- the v4 address's
	// offset within Pool, added to this prefix's base -- rather than drawn from
	// a second pool. That is a deliberate departure from OpenVPN's own
	// --ifconfig-ipv6-pool, and the reason is lifecycle rather than taste: a
	// second allocator is a second thing to release, on a path (reapClient)
	// that has exactly one chance to run and no peer to confirm it with.
	// Derivation is 1:1 with the v4 assignment by construction, so releasing
	// the v4 address releases both, and it makes the mapping legible --
	// 10.8.0.2 becomes fd00:8::2.
	Pool6 string
	// DNS servers pushed to clients.
	DNS []net.IP
	// MTU pushed to clients as tun-mtu (0 uses the default).
	MTU int

	// TLSCrypt and TLSAuth are an OpenVPN static key (the "OpenVPN Static key
	// V1" format) protecting the control channel, matching the client's
	// --tls-crypt / --tls-auth. TLSCrypt takes precedence. Both are optional and
	// neither changes the data channel.
	//
	// Setting one is what makes the server unanswerable to a peer that does not
	// hold the key: without it, a bare P_CONTROL_HARD_RESET_CLIENT_V2 from any
	// source is answered with a server hard reset and then the full certificate
	// flight, which is the active-probe stage of the OpenVPN fingerprinting work
	// (Xue et al., USENIX Security 2022). With one, an opener that fails the
	// HMAC is dropped before any session state exists.
	//
	// A client configured with --tls-crypt also cannot talk to a server without
	// this: the wrapping is not negotiated, so the two sides must agree.
	TLSCrypt []byte
	TLSAuth  []byte
	// Auth is the --auth digest for TLSAuth's HMAC (default SHA1). It is unused
	// with TLSCrypt, which fixes its own construction.
	Auth string
	// KeyDirection is the client's --key-direction for TLSAuth: 0 or 1, or -1
	// (the default) for a bidirectional key. The server takes the opposite
	// direction to the client automatically.
	KeyDirection int

	// TUNName is the desired TUN interface name; empty lets the kernel pick.
	TUNName string

	// Shape enables downstream traffic shaping: how much padded output each
	// inner flow is given before shaping stops for that flow, so it bounds what
	// shaping costs. A flow gets Shape/MTU padded packets whatever sizes it
	// carries. Zero, the default, disables it.
	//
	// It hides the size pattern of an inner TLS handshake, which otherwise shows
	// through as the size of the data packet carrying it (see
	// dataplane/shape.go). Clients need no support for it: the data channel
	// length-delimits its payload, so filler past the inner IP packet is
	// delimited by that packet's own header and a stock `openvpn` trims it.
	// dataplane.DefaultShapeBytes is a reasonable value.
	//
	// This is a different defence from TLSCrypt above: that one hides the
	// tunnel's own handshake from an active probe, this one hides the size
	// pattern of what the tunnel carries.
	Shape int

	// Logger receives progress logs; nil discards them.
	Logger *slog.Logger

	// PostQuantumOnly requires a post-quantum key exchange and ML-DSA
	// authentication, refusing anything less rather than negotiating down. It is
	// what the pq-openvpn registry name sets; see internal/pqpolicy for the contract
	// and doc/pq-variants-plan.md for why it is a name rather than a flag.
	PostQuantumOnly bool
}

// Validate reports whether a ServerConfig has what a server cannot start
// without. NewServer runs it; it is exported so the public package can say so
// before it opens anything.
func (c *ServerConfig) Validate() error {
	switch {
	case len(c.CA) == 0:
		return errors.New("openvpn: server CA is required")
	case len(c.Cert) == 0 || len(c.Key) == 0:
		return errors.New("openvpn: server certificate and key are required")
	case len(c.TLSCrypt) > 0 && len(c.TLSAuth) > 0:
		return errors.New("openvpn: tls-crypt and tls-auth are mutually exclusive")
	}
	return nil
}

// serverWrapperFactory returns a function that mints one control-channel
// wrapper, or nil for the plain profile.
//
// It is a factory rather than a single shared Wrapper because each wrapper owns
// a send counter and an anti-replay window, and those are per-connection: one
// window shared across clients would reject the second client's packet ID 1 as
// a replay of the first's.
//
// The server takes the direction opposite the client's. tls-crypt fixes the
// client at Inverse, so the server is Normal; tls-auth follows the client's
// --key-direction, which the caller passes through unchanged.
func serverWrapperFactory(cfg *ServerConfig) (func() (control.Wrapper, error), error) {
	switch {
	case len(cfg.TLSCrypt) > 0:
		key, err := tlswrap.ParseStaticKey(cfg.TLSCrypt)
		if err != nil {
			return nil, fmt.Errorf("openvpn: tls-crypt key: %w", err)
		}
		return func() (control.Wrapper, error) { return tlswrap.NewCrypt(key, tlswrap.Normal) }, nil
	case len(cfg.TLSAuth) > 0:
		key, err := tlswrap.ParseStaticKey(cfg.TLSAuth)
		if err != nil {
			return nil, fmt.Errorf("openvpn: tls-auth key: %w", err)
		}
		digest, err := tlswrap.ParseDigest(cfg.Auth)
		if err != nil {
			return nil, fmt.Errorf("openvpn: tls-auth: %w", err)
		}
		dir := serverAuthDirection(cfg.KeyDirection)
		return func() (control.Wrapper, error) { return tlswrap.NewAuth(key, dir, digest), nil }, nil
	default:
		return nil, nil
	}
}

// serverAuthDirection mirrors authDirection: the server takes the slot pair the
// client does not. A bidirectional key (--key-direction unset) uses slot 0 both
// ways on both sides, so it is its own opposite.
func serverAuthDirection(keyDirection int) tlswrap.Direction {
	switch keyDirection {
	case 0:
		return tlswrap.Inverse
	case 1:
		return tlswrap.Normal
	default:
		return tlswrap.Bidirectional
	}
}

// Server is a running OpenVPN responder: one UDP socket serving many clients, a
// TUN device, an address pool, and the shared data-path pump. It owns the TUN but
// does not configure host networking — Gateway and Network report what a caller
// needs to do that itself.
type Server struct {
	tlsCfg *tls.Config
	// newWrapper mints a per-client control-channel wrapper, or is nil for the
	// plain profile. See serverWrapperFactory for why it is a factory.
	newWrapper func() (control.Wrapper, error)
	pool       *dataplane.AddrPool
	gateway    net.IP
	// pool6 is the tunnel's IPv6 prefix, zero when the tunnel is IPv4-only, and
	// gateway6 the server's own address inside it. There is no v6 allocator:
	// see ServerConfig.Pool6 for why a client's v6 address is derived from its
	// v4 one instead.
	pool6    netip.Prefix
	gateway6 netip.Addr
	dns      []net.IP
	mtu      int
	shape    int
	logger   *vlog.Logger
	gate     *dataplane.Gate

	listenAddr *net.UDPAddr
	tun        *dataplane.TUN
	conn       *dataplane.PacketConn
	pump       *dataplane.Pump

	nextPeerID atomic.Uint32

	mu      sync.Mutex
	clients map[string]*serverClient

	closeOnce sync.Once
	closed    chan struct{}
}

// NewServer builds a server from cfg: it parses the certificates and pool and
// opens the TUN device. It does not bind the socket until ListenAndServe. Opening
// a TUN device requires CAP_NET_ADMIN.
func NewServer(cfg ServerConfig) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	tlsCfg, err := serverTLSConfig(&cfg)
	if err != nil {
		return nil, fmt.Errorf("openvpn: %w", err)
	}
	newWrapper, err := serverWrapperFactory(&cfg)
	if err != nil {
		return nil, err
	}

	poolCIDR := cfg.Pool
	if poolCIDR == "" {
		poolCIDR = "10.8.0.0/24"
	}
	pool, gateway, err := dataplane.NewAddrPool(poolCIDR)
	if err != nil {
		return nil, fmt.Errorf("openvpn: pool: %w", err)
	}

	var pool6 netip.Prefix
	var gateway6 netip.Addr
	if cfg.Pool6 != "" {
		if pool6, err = netip.ParsePrefix(cfg.Pool6); err != nil {
			return nil, fmt.Errorf("openvpn: pool6: %w", err)
		}
		if !pool6.Addr().Is6() || pool6.Addr().Is4In6() {
			return nil, fmt.Errorf("openvpn: pool6 %q is not an IPv6 prefix", cfg.Pool6)
		}
		pool6 = pool6.Masked()
		// Check the prefix against the *largest* address the pool can hand out,
		// not against the gateway. The gateway is the pool's first host, so
		// deriving it proves nothing about the client at the far end -- and a
		// derivation that wrapped would put two clients on one address, which
		// is a routing bug that looks like packet loss.
		if err := prefix6Fits(pool6, pool.Network()); err != nil {
			return nil, fmt.Errorf("openvpn: pool6: %w", err)
		}
		if gateway6, err = derive6(pool6, pool.Network(), gateway); err != nil {
			return nil, fmt.Errorf("openvpn: pool6: %w", err)
		}
	}

	port := cfg.ListenPort
	if port == 0 {
		port = 1194
	}
	listenIP := net.ParseIP(cfg.ListenIP)
	if cfg.ListenIP == "" {
		listenIP = net.IPv4zero
	}
	if listenIP == nil {
		return nil, fmt.Errorf("openvpn: invalid listen IP %q", cfg.ListenIP)
	}

	logger := vlog.From(cfg.Logger)
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}

	// GSO: the kernel may hand the pump TCP super-frames to segment and batch
	// (doc/scaling-the-data-path.md); falls back to a plain TUN transparently.
	tun, err := dataplane.OpenTUNGSO(cfg.TUNName)
	if err != nil {
		return nil, fmt.Errorf("openvpn: open TUN: %w", err)
	}

	return &Server{
		tlsCfg:     tlsCfg,
		newWrapper: newWrapper,
		gate:       dataplane.NewGate(dataplane.AdmissionConfig{}),
		pool:       pool,
		gateway:    gateway,
		pool6:      pool6,
		gateway6:   gateway6,
		dns:        cfg.DNS,
		mtu:        mtu,
		shape:      cfg.Shape,
		logger:     logger,
		listenAddr: &net.UDPAddr{IP: listenIP, Port: port},
		tun:        tun,
		clients:    make(map[string]*serverClient),
		closed:     make(chan struct{}),
	}, nil
}

// TUNName is the interface the data path is bound to.
func (s *Server) TUNName() string { return s.tun.Name() }

// Gateway is the server's own tunnel-side address (the pool's first host).
func (s *Server) Gateway() net.IP { return s.gateway }

// Network is the tunnel subnet, for routing and NAT rules.
func (s *Server) Network() *net.IPNet { return s.pool.Network() }

// Gateway6 is the server's own tunnel-side IPv6 address, or the zero Addr when
// the server was configured without an IPv6 prefix.
//
// It and Network6 implement client.DualStackServer, which carries the v6 half
// through to internal/hostnet: the interface address, forwarding, and the
// ip6tables MASQUERADE and FORWARD rules. Without them a client could be pushed
// a v6 address it could not reach anything with.
func (s *Server) Gateway6() netip.Addr { return s.gateway6 }

// Network6 is the tunnel's IPv6 prefix, for routing and NAT rules.
func (s *Server) Network6() netip.Prefix { return s.pool6 }

// Server implements client.DualStackServer. Asserted here so renaming either
// method is a compile error rather than a listener that silently stops
// configuring v6.
var _ client.DualStackServer = (*Server)(nil)

// prefix6Fits reports whether every address the v4 pool can hand out maps to a
// distinct address inside prefix. A /64 has 64 host bits and a /24 pool needs
// eight, so this only refuses a deliberately tiny prefix -- where silently
// wrapping two clients onto one address would be far worse.
func prefix6Fits(prefix netip.Prefix, network *net.IPNet) error {
	poolBits, _ := network.Mask.Size()
	need := 32 - poolBits
	if host := 128 - prefix.Bits(); host < need {
		return fmt.Errorf("%s has %d host bits, too few for the %d a %s pool needs",
			prefix, host, need, network)
	}
	return nil
}

// client6 is the IPv6 address a client holding ip is given, or false when the
// server has no v6 prefix. A derivation that fails here cannot: NewServer has
// already proved the prefix has room for every address the pool can hand out.
func (s *Server) client6(ip net.IP) (netip.Addr, bool) {
	if !s.pool6.IsValid() {
		return netip.Addr{}, false
	}
	addr, err := derive6(s.pool6, s.pool.Network(), ip)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr, true
}

// derive6 maps an address inside the v4 pool to its address inside the v6
// prefix, by adding the v4 address's offset within its network to the prefix's
// base. 10.8.0.2 in 10.8.0.0/24 under fd00:8::/64 becomes fd00:8::2.
//
// The mapping is total and injective over the pool, which is what lets it stand
// in for a second allocator: two clients cannot collide because their v4
// addresses cannot, and nothing has to be released because nothing was taken.
func derive6(prefix netip.Prefix, network *net.IPNet, ip net.IP) (netip.Addr, error) {
	v4 := ip.To4()
	base := network.IP.To4()
	if v4 == nil || base == nil {
		return netip.Addr{}, fmt.Errorf("%s is not an IPv4 address in %s", ip, network)
	}
	offset := binary.BigEndian.Uint32(v4) - binary.BigEndian.Uint32(base)

	addr := prefix.Addr().As16()
	binary.BigEndian.PutUint32(addr[12:16], binary.BigEndian.Uint32(addr[12:16])+offset)
	return netip.AddrFrom16(addr), nil
}

// ListenAndServe binds the UDP socket, starts the data path, and serves clients
// until Close. It blocks.
func (s *Server) ListenAndServe() error {
	conn, err := net.ListenUDP("udp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("openvpn: listen: %w", err)
	}
	s.conn = dataplane.NewPacketConn(conn)

	// The pump routes TUN packets to a client tunnel by destination /32, and sends
	// each encapsulated packet to that tunnel's current peer address; inbound data
	// packets are demuxed by their P_DATA_V2 peer-id.
	send := func(pkt []byte, to *net.UDPAddr) {
		if to == nil {
			return
		}
		if _, werr := conn.WriteToUDP(pkt, to); werr != nil {
			s.logger.Printf("openvpn: send to %s: %v", to, werr)
		}
	}
	s.pump = dataplane.NewPump(s.tun, send, serverDataDemux, s.logger.Slog())
	// GSO bursts flush with one sendmmsg, source-pinned like every send.
	s.pump.SetBatchSender(func(pkts [][]byte, to *net.UDPAddr) {
		if to == nil {
			return
		}
		if _, werr := s.conn.WriteBatch(pkts, to); werr != nil {
			s.logger.Printf("openvpn: batch send to %s: %v", to, werr)
		}
	})
	s.pump.SetInnerMTU(s.mtu)
	if s.shape > 0 {
		s.pump.SetShaper(dataplane.NewShaper(dataplane.ShapeConfig{Bytes: s.shape}))
		s.logger.Printf("openvpn: downstream shaping on, %d bytes per flow", s.shape)
	}
	go s.pump.Run()

	s.logger.Printf("openvpn: listening on %s, gateway %s", s.listenAddr, s.gateway)
	s.readLoop()
	return nil
}

// readLoop reads datagrams from every client on the shared socket and dispatches
// each by opcode: data packets to the pump, control packets to the owning (or a
// new) client session. Reads are batched (dataplane.PacketConn.ReadBatch): one
// recvmmsg drains up to readBatch datagrams under load and blocks like a plain
// read when idle.
func (s *Server) readLoop() {
	const readBatch = 16
	bufs := make([][]byte, readBatch)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	sizes := make([]int, readBatch)
	froms := make([]*net.UDPAddr, readBatch)
	dataPkts := make([][]byte, 0, readBatch)
	dataFroms := make([]*net.UDPAddr, 0, readBatch)
	for {
		n, err := s.conn.ReadBatch(bufs, sizes, froms)
		dataPkts, dataFroms = dataPkts[:0], dataFroms[:0]
		for i := range n {
			pkt, from := bufs[i][:sizes[i]], froms[i]
			op, keyID, ok := wire.Opcode(pkt)
			if !ok {
				continue
			}
			switch {
			case data.IsDataOpcode(op):
				// Collected without a copy: the whole batch goes to the pump
				// at once so inbound TCP can coalesce (GRO); the pump decrypts
				// in place and writes the TUN before returning — bufs[i] is
				// not touched again until the next ReadBatch.
				dataPkts = append(dataPkts, pkt)
				dataFroms = append(dataFroms, from)
			case wire.IsControl(op):
				// Copied out: control handling queues the packet to the owning
				// session, beyond this batch's buffers.
				s.handleControl(op, keyID, append([]byte(nil), pkt...), from)
			}
		}
		if len(dataPkts) > 0 {
			s.pump.HandleInboundBatch(dataPkts, dataFroms)
		}
		if err != nil {
			return // socket closed
		}
	}
}

// handleControl routes a control datagram to its client session, creating one
// when a new client opens with a hard reset.
func (s *Server) handleControl(op, keyID uint8, pkt []byte, from *net.UDPAddr) {
	key := from.String()
	s.mu.Lock()
	cl, exists := s.clients[key]
	if !exists {
		if op != wire.PControlHardResetClientV2 {
			s.mu.Unlock()
			return // not a known session and not a new-connection opener
		}
		// With a protected control channel, prove the opener holds the static
		// key before anything is created for it. This has to happen here rather
		// than inside the Channel, because constructing a Channel queues the
		// server hard reset immediately — so by the time Unwrap could reject the
		// packet, the reply an active prober is looking for has already gone out.
		//
		// Failing here costs the prober a datagram and yields silence.
		if !s.authenticateOpener(pkt) {
			s.mu.Unlock()
			return
		}
		// A new session means a TLS handshake and the key exchange behind it,
		// all for an unauthenticated peer on a spoofable UDP source.
		if r := s.gate.Admit(from); r != dataplane.Admitted {
			s.mu.Unlock()
			s.logger.Warnf("openvpn: refusing new client %s: %v", from, r)
			return
		}
		cl, err := s.newClient(from, keyID)
		if err != nil {
			s.gate.Done()
			s.mu.Unlock()
			s.logger.Printf("openvpn: client %s: %v", from, err)
			return
		}
		s.clients[key] = cl
		s.mu.Unlock()
		cl.ch.Deliver(pkt)
		go func() {
			// The reservation is held for the whole handshake, which is the
			// expensive part; once it returns the client is either established
			// or gone.
			defer s.gate.Done()
			s.handshake(cl)
		}()
		return
	}
	s.mu.Unlock()
	cl.ch.Deliver(pkt)
}

// authenticateOpener reports whether a would-be new client's first datagram
// carries a valid control-channel wrapping. It always passes on the plain
// profile, which has nothing to check.
//
// The wrapper it builds is thrown away: its only job is to answer the question,
// and the session gets a fresh one whose anti-replay window has not yet seen
// this packet. That costs one extra HMAC per connection attempt — per
// connection, never per packet — and keeps the check from having to reach into
// the Channel's state.
func (s *Server) authenticateOpener(pkt []byte) bool {
	if s.newWrapper == nil {
		return true
	}
	w, err := s.newWrapper()
	if err != nil {
		return false
	}
	_, err = w.Unwrap(pkt)
	return err == nil
}

// newClient builds the control channel for a freshly-seen client. Its send
// closure targets the client's current address on the shared socket.
func (s *Server) newClient(from *net.UDPAddr, keyID uint8) (*serverClient, error) {
	dst := *from
	send := func(b []byte) error {
		_, err := s.conn.WriteToUDP(b, &dst)
		return err
	}
	var wrap control.Wrapper
	if s.newWrapper != nil {
		var err error
		if wrap, err = s.newWrapper(); err != nil {
			return nil, fmt.Errorf("control channel wrapper: %w", err)
		}
	}
	ch, err := control.NewServer(send, keyID, controlTimeout, wrap)
	if err != nil {
		return nil, fmt.Errorf("control channel: %w", err)
	}
	return &serverClient{ch: ch, addr: from, keyID: keyID}, nil
}

// handshake runs the server side of the post-reset negotiation for one client:
// TLS, the key_method_2 exchange, and the config push, then installs the client's
// data tunnel in the pump.
func (s *Server) handshake(cl *serverClient) {
	deadline := time.Now().Add(handshakeTimeout)
	_ = cl.ch.SetDeadline(deadline)

	tlsConn := tls.Server(cl.ch, s.tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		s.dropClient(cl, fmt.Sprintf("TLS handshake: %v", err))
		return
	}
	s.logger.Printf("openvpn: client %s TLS established, reading keys", cl.addr)

	hello, err := readClientKeys(tlsConn)
	if err != nil {
		s.dropClient(cl, fmt.Sprintf("read client keys: %v", err))
		return
	}

	serverKS, err := keys.NewServerKeySource()
	if err != nil {
		s.dropClient(cl, err.Error())
		return
	}
	if _, err := tlsConn.Write(serverKS.MarshalServer(s.occOptions())); err != nil {
		s.dropClient(cl, fmt.Sprintf("send server keys: %v", err))
		return
	}

	if err := readPushRequest(tlsConn); err != nil {
		s.dropClient(cl, fmt.Sprintf("await push request: %v", err))
		return
	}

	ip, err := s.pool.Allocate()
	if err != nil {
		s.dropClient(cl, fmt.Sprintf("allocate address: %v", err))
		return
	}
	peerID := s.nextPeerID.Add(1)

	// Derive the AES-256-GCM data keys as the server (the reverse direction of the
	// client), and build the cipher tagged with the peer-id we just assigned.
	remoteSID, _ := cl.ch.RemoteSessionID()
	clientSID := keys.SessionID(remoteSID)
	serverSID := keys.SessionID(cl.ch.LocalSessionID())
	ks2 := &keys.KeySource2{Client: hello.KeySource, Server: *serverKS}
	dk := ks2.Derive(clientSID, serverSID, true)
	cipher, err := data.New(dk, peerID, cl.keyID)
	if err != nil {
		s.pool.Release(ip)
		s.dropClient(cl, fmt.Sprintf("data cipher: %v", err))
		return
	}

	if _, err := tlsConn.Write(s.buildPushReply(ip, peerID)); err != nil {
		s.pool.Release(ip)
		s.dropClient(cl, fmt.Sprintf("send push reply: %v", err))
		return
	}
	_ = cl.ch.SetDeadline(time.Time{})

	ipAddr, _ := netip.AddrFromSlice(ip.To4())
	routes := []netip.Prefix{netip.PrefixFrom(ipAddr, 32)}
	if addr6, ok := s.client6(ip); ok {
		// The pump's route trie is per-family, so a /128 beside the /32 is all
		// that is needed for outbound v6 to find this client.
		routes = append(routes, netip.PrefixFrom(addr6, 128))
	}
	tun := &serverTunnel{
		cipher: cipher,
		peerID: peerID,
		routes: routes,
	}
	tun.peer.Store(cl.addr)

	cl.tunnel = tun
	cl.assignedIP = ip
	cl.upAt = time.Now()
	s.pump.AddTunnel(tun)

	s.logger.Printf("openvpn: client %s up, assigned %s (peer-id %d)", cl.addr, ip, peerID)
	go s.serveClient(cl)
}

// serveClient owns one established client for as long as it is alive. It sends
// the data-channel ping the pushed keepalive promises, and it is the only thing
// that ever notices the client is gone. Both are on one ticker because they are
// the same question asked in opposite directions.
//
// A UDP client never says goodbye. It stops answering, and if nothing is
// listening for that silence its address, its tunnel and its map entry stay
// behind for the life of the process -- which is what this server did until
// this function did more than ping.
func (s *Server) serveClient(cl *serverClient) {
	tick := time.NewTicker(keepaliveInterval)
	defer tick.Stop()
	for {
		select {
		case <-s.closed:
			// The server is going away and is closing the pump and the TUN
			// behind us. Reaping here would release into an allocator nobody
			// will read again, through a pump that is already shutting down.
			return
		case <-cl.ch.Closed():
			s.reapClient(cl, "control channel closed")
			return
		case <-tick.C:
			if silent, gone := s.silentFor(cl); gone {
				s.reapClient(cl, fmt.Sprintf("silent for %s", silent.Round(time.Second)))
				return
			}
			pkt, err := cl.tunnel.cipher.Seal(data.Ping)
			if err != nil {
				return
			}
			if to := cl.tunnel.PeerAddr(); to != nil {
				_, _ = s.conn.WriteToUDP(pkt, to)
			}
		}
	}
}

// silentFor reports how long the client has been silent, and whether that is
// past pingRestart.
//
// The clock is the pump's own per-tunnel LastSeen, which moves on any
// authenticated inbound packet -- including a keepalive ping, which decapsulates
// to nothing and is counted anyway for exactly this reason. So an idle tunnel
// with a present client is never reaped, and the check costs the data path
// nothing: it reads a counter the hot path was already writing.
func (s *Server) silentFor(cl *serverClient) (time.Duration, bool) {
	last := cl.upAt
	if st, ok := s.pump.TunnelStats(cl.tunnel); ok && !st.LastSeen.IsZero() {
		last = st.LastSeen
	}
	d := time.Since(last)
	return d, d > pingRestart
}

// reapClient tears down an established client: the tail of handshake undone, in
// reverse. It is idempotent -- the liveness tick and a closed control channel
// can both reach it -- and it is the only path that releases an address.
func (s *Server) reapClient(cl *serverClient, reason string) {
	if !cl.reaped.CompareAndSwap(false, true) {
		return
	}
	cl.ch.Close()
	s.pump.RemoveTunnel(cl.tunnel)
	s.pool.Release(cl.assignedIP)

	s.mu.Lock()
	// Only when the map still names THIS session. A client that reconnected
	// from the same address before its old session was reaped owns the key now,
	// and deleting it would strand the new session's control channel while
	// leaving its tunnel in the pump -- a worse leak than the one being fixed.
	if cur, ok := s.clients[cl.addr.String()]; ok && cur == cl {
		delete(s.clients, cl.addr.String())
	}
	s.mu.Unlock()

	s.logger.Printf("openvpn: client %s down, released %s: %s", cl.addr, cl.assignedIP, reason)
}

// dropClient tears down a half-open client after a handshake failure.
func (s *Server) dropClient(cl *serverClient, reason string) {
	s.logger.Warnf("openvpn: client %s dropped: %s", cl.addr, reason)
	cl.ch.Close()
	s.mu.Lock()
	delete(s.clients, cl.addr.String())
	s.mu.Unlock()
}

// occOptions is the server's advisory OCC options string, matching the client's
// AES-256-GCM profile from the responder side.
func (s *Server) occOptions() string {
	return "V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-server"
}

// buildPushReply constructs the NUL-terminated PUSH_REPLY: the subnet-topology
// address assignment, the tunnel gateway, the negotiated cipher and peer-id, the
// keepalive timers, and any DNS servers.
func (s *Server) buildPushReply(ip net.IP, peerID uint32) []byte {
	var b strings.Builder
	b.WriteString("PUSH_REPLY")
	fmt.Fprintf(&b, ",route-gateway %s", s.gateway)
	b.WriteString(",topology subnet")
	b.WriteString(",ping 10,ping-restart 60")
	fmt.Fprintf(&b, ",ifconfig %s %s", ip, s.pool.Netmask())
	if addr6, ok := s.client6(ip); ok {
		// RFC-free territory: this is OpenVPN's own option, and its argument
		// order is the client's address first and the peer's second -- the
		// opposite way round from --ifconfig on the command line, which names
		// the local address then the remote. Getting it backwards produces a
		// client that configures the server's address on its own interface,
		// which looks like a routing problem and is not one.
		fmt.Fprintf(&b, ",ifconfig-ipv6 %s/%d %s", addr6, s.pool6.Bits(), s.gateway6)
		fmt.Fprintf(&b, ",route-ipv6-gateway %s", s.gateway6)
	}
	for _, d := range s.dns {
		fmt.Fprintf(&b, ",dhcp-option DNS %s", d)
	}
	fmt.Fprintf(&b, ",tun-mtu %d", s.mtu)
	b.WriteString(",cipher AES-256-GCM")
	fmt.Fprintf(&b, ",peer-id %d", peerID)
	return append([]byte(b.String()), 0)
}

// Close stops the server: the socket, the pump, and the TUN. It is idempotent.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		if s.pump != nil {
			s.pump.Close()
		}
		if s.conn != nil {
			s.conn.Close()
		}
		if s.tun != nil {
			s.tun.Close()
		}
	})
	return nil
}

// Abandon implements client.AbandonableServer. It closes the TUN directly, so
// an abandoned listener's packet pump unparks and its fd is released even
// though Close never returned. See client.AbandonableServer for why this is not
// simply Close.
//
// The TUN is set in NewServer and never reassigned, so this reads it without the
// lock Close takes -- deliberately, because a wedged Close may be holding that
// lock. The nil check mirrors Close's.
func (s *Server) Abandon() {
	if s.tun != nil {
		s.tun.Close()
	}
}

// Server implements client.AbandonableServer, so the supervisor can take its
// descriptors back when Close overruns. Asserted here because the interface is
// found by type assertion at the one call site: without this, a renamed or
// re-signatured Abandon compiles fine and the assertion silently starts failing,
// which reads as the leak coming back.
var _ client.AbandonableServer = (*Server)(nil)

// serverClient is one accepted client's control-channel state plus, once up, its
// data tunnel and assignment.
type serverClient struct {
	ch    *control.Channel
	addr  *net.UDPAddr
	keyID uint8

	tunnel     *serverTunnel
	assignedIP net.IP
	// upAt is when the client was established, and it is the liveness clock
	// until the first inbound data packet moves the pump's own LastSeen. A
	// client that completes the handshake and never speaks again is still on a
	// clock; without this it would be silent since the zero time and reaped on
	// the first tick.
	upAt time.Time
	// reaped guards the teardown, which the liveness tick and a closed control
	// channel can both reach.
	reaped atomic.Bool
}

// serverTunnel is the data-path view of one client, implementing dataplane.Tunnel:
// TUN packets destined to its /32 are sealed to it, and its inbound data packets
// are opened (dropping keepalive pings).
type serverTunnel struct {
	cipher *data.Cipher
	peerID uint32
	routes []netip.Prefix
	peer   atomic.Pointer[net.UDPAddr]
}

func (t *serverTunnel) InboundKey() uint32                   { return t.peerID }
func (t *serverTunnel) Routes() []netip.Prefix               { return t.routes }
func (t *serverTunnel) PeerAddr() *net.UDPAddr               { return t.peer.Load() }
func (t *serverTunnel) Encapsulate(p []byte) ([]byte, error) { return t.cipher.Seal(p) }

// EncapsulatePadded implements dataplane.PaddingTunnel. The data channel
// length-delimits its payload, so filler past the inner IP packet is delimited
// by that packet's own header and is inert to any conforming receiver.
func (t *serverTunnel) EncapsulatePadded(p []byte, minInner int) ([]byte, error) {
	return t.cipher.SealPadded(p, minInner)
}

func (t *serverTunnel) Decapsulate(pkt []byte) ([]byte, error) {
	pt, err := t.cipher.Open(pkt)
	if err != nil {
		return nil, err
	}
	if data.IsPing(pt) {
		return nil, nil // keepalive: authenticated but nothing to deliver
	}
	// Trim any shaping filler past the inner packet; the data channel delimits
	// its payload by length, so only the IP header says where the packet ends.
	inner := dataplane.TrimToIP(pt)
	if inner == nil {
		return nil, errNotIP
	}
	return inner, nil
}

// serverTLSConfig builds the mutual-TLS config for the responder: the server's
// certificate, and RequireAndVerifyClientCert against the CA (OpenVPN's trust
// model is the shared CA, not hostnames).
func serverTLSConfig(cfg *ServerConfig) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("server certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cfg.CA) {
		return nil, errors.New("ca: no certificates parsed")
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		// SessionTicketsDisabled is what allows TLS 1.3 here, and it is not a
		// privacy setting.
		//
		// This used to be capped at TLS 1.2, because OpenVPN runs TLS over its
		// own reliable control channel and TLS 1.3's post-handshake
		// NewSessionTicket messages do not fit that half-duplex
		// request/response model cleanly -- they stalled clients before they
		// sent key_method_2. The cap fixed the stall and cost the server half of
		// OpenVPN its post-quantum key exchange, since Go's default
		// CurvePreferences lead with X25519MLKEM768 and only TLS 1.3 has a
		// key_share to carry it. Every other TLS protocol here was hybrid and
		// this one was classical.
		//
		// Suppressing the tickets removes the actual cause rather than the
		// version that exposed it: the server emits no NewSessionTicket, so
		// there is nothing to arrive out of turn. Tickets buy nothing here
		// anyway -- OpenVPN negotiates one TLS session per tunnel and resumes
		// nothing.
		//
		// Verified against the real `openvpn` binary rather than reasoned about:
		// every OpenVPN interop cell passes with this -- plain, tls-auth,
		// tls-crypt, shaped, CBC, and the veepin-to-veepin pair. If a client is
		// ever found that still stalls, cap that path and name the client;
		// do not restore a blanket cap whose reason had a narrower cause.
		SessionTicketsDisabled: true,
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              pool,
	}
	if cfg.PostQuantumOnly {
		// This was declared, set from the registry, and never read: `veepin
		// serve pq-openvpn` built exactly the config above and accepted a
		// classical peer, an RSA certificate and TLS 1.2, while its name
		// promised a refusal. The client half (clientTLSConfig) had always
		// hardened, so the veepin<->veepin cell passed and so did every unit
		// test -- the one direction that mattered was the one nothing drove.
		//
		// Checked before the TUN is opened and before anything binds: NewServer
		// calls this first, so an operator who pointed a pq- name at their
		// existing RSA certificate learns it here rather than from a listener
		// that comes up and then refuses every client.
		if err := pqpolicy.CheckCredential(cert); err != nil {
			return nil, err
		}
		// Mutual TLS, so HardenTLS covers both directions at once: it raises
		// the floor to 1.3, pins the curves, and chains RequireMLDSALeaf onto
		// the peer check -- which here runs against the CLIENT's certificate,
		// since this is the side that asked for one.
		pqpolicy.HardenTLS(tlsCfg)
	}
	return tlsCfg, nil
}

// readClientKeys reads TLS bytes until a complete client key_method_2 message is
// present, then parses it.
func readClientKeys(tlsConn *tls.Conn) (*keys.ClientHello, error) {
	buf := make([]byte, 0, 512)
	tmp := make([]byte, 4096)
	for {
		n, err := tlsConn.Read(tmp)
		if err != nil {
			return nil, err
		}
		buf = append(buf, tmp[:n]...)
		h, perr := keys.ParseClient(buf)
		if perr == nil {
			return h, nil
		}
		if !errors.Is(perr, keys.ErrShortMessage) {
			return nil, perr
		}
		if len(buf) > 8192 {
			return nil, errors.New("client key message too long")
		}
	}
}

// readPushRequest reads TLS control strings until a PUSH_REQUEST arrives, so a
// client that repeats it (until it gets a reply) is handled.
func readPushRequest(tlsConn *tls.Conn) error {
	buf := make([]byte, 0, 128)
	tmp := make([]byte, 512)
	for {
		n, err := tlsConn.Read(tmp)
		if err != nil {
			return err
		}
		buf = append(buf, tmp[:n]...)
		for {
			i := indexByte(buf, 0)
			if i < 0 {
				break
			}
			msg := string(buf[:i])
			buf = buf[i+1:]
			if strings.HasPrefix(msg, "PUSH_REQUEST") {
				return nil
			}
			// Ignore other control strings (e.g. an early OCC exchange).
		}
		if len(buf) > 4096 {
			return errors.New("push request not seen")
		}
	}
}

func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}

// serverDataDemux extracts the P_DATA_V2 peer-id (bytes 1..3) as the pump's
// inbound key, so each client's packets route to the tunnel keyed by the peer-id
// the server assigned it. P_DATA_V1 (no peer-id) is not accepted.
func serverDataDemux(pkt []byte) (uint32, bool) {
	op, _, ok := wire.Opcode(pkt)
	if !ok || op != wire.PDataV2 || len(pkt) < 4 {
		return 0, false
	}
	return uint32(pkt[1])<<16 | uint32(pkt[2])<<8 | uint32(pkt[3]), true
}
