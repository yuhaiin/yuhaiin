package ike

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/ikev2/eap"
	"github.com/xen0bit/veepin/internal/ikev2/payload"
	"github.com/xen0bit/veepin/internal/vlog"
)

// Config configures the IKEv2 server.
type Config struct {
	// ListenIP is the local IP to bind both IKE sockets on (default 0.0.0.0).
	ListenIP string
	// Port500 / Port4500 are the IKE and NAT-T ports (defaults 500 and 4500).
	// They are overridable mainly for tests.
	Port500  int
	Port4500 int

	// PSK is the pre-shared key used for authentication of every peer.
	PSK []byte
	// LocalID is the identity this server presents in IKE_AUTH.
	LocalID Identity

	// ServerCert, if set, authenticates the server with an X.509 certificate
	// (RFC 7427 digital signature) instead of the PSK. It is required to accept
	// certificate-authenticating clients, and its subject/SANs should match
	// LocalID so a peer's identity check passes.
	ServerCert *tls.Certificate
	// ClientCAs, if set, enables certificate authentication for clients and is
	// the trust anchor their certificates must chain to.
	ClientCAs *x509.CertPool

	// EAPCredentials, if non-nil, enables EAP-MSCHAPv2 username/password
	// authentication. When a client omits the AUTH payload in IKE_AUTH (asking
	// to use EAP), the server runs EAP-MSCHAPv2 against this lookup. The server
	// still authenticates itself to the client with PSK. If nil, only PSK auth
	// is offered.
	EAPCredentials eap.CredentialLookup
	// EAPServerName is advertised in the MSCHAPv2 challenge (cosmetic).
	EAPServerName string

	// LocalTS / RemoteTS are the traffic selectors this server offers. If empty,
	// a permissive 0.0.0.0/0 all-ports selector is used.
	LocalTS  []payload.TrafficSelector
	RemoteTS []payload.TrafficSelector

	// PublicIP is the server's own address as reachable by clients. It is used
	// for NAT detection hashes. If nil, detection still works but may over-report
	// NAT; setting it improves accuracy.
	PublicIP net.IP

	// RequirePostQuantum refuses any IKE SA whose key exchange is classical
	// only: the initiator must both propose an ADDKE1 method this server
	// supports (ML-KEM-768, RFC 9370) and advertise
	// INTERMEDIATE_EXCHANGE_SUPPORTED, since the exchange that carries it is
	// the one thing it cannot be done without.
	//
	// The default responder ACCEPTS post-quantum opportunistically and completes
	// classically when the initiator offers nothing -- which is right for
	// "ikev2" and wrong for "pq-ikev2", where an initiator that simply omits the
	// transform would otherwise get a classical SA and nothing would object.
	// This is the whole of what the variant name buys on the key-exchange side.
	RequirePostQuantum bool

	// RequirePostQuantumAuth additionally refuses classical public-key
	// authentication: an RSA or ECDSA certificate is rejected and only ML-DSA
	// (FIPS 204) is accepted.
	//
	// PSK authentication is deliberately still permitted. A pre-shared key is
	// symmetric and is not broken by a quantum adversary -- that is the entire
	// premise of RFC 8784, which exists to give IKEv2 quantum resistance using
	// exactly this property. Refusing it would be cargo-culting the word
	// "post-quantum" rather than applying it.
	//
	// EAP-MSCHAPv2 IS refused, and for a reason that has nothing to do with
	// quantum computers: its own primitives are MD4 and single-DES, which are
	// broken classically. A name promising maximum assurance should not accept
	// it.
	RequirePostQuantumAuth bool

	// TCP additionally listens for RFC 8229/9329 TCP-encapsulated IKE and ESP on
	// Port4500. It is additive: the UDP sockets stay bound, so a peer reaches
	// this server on whichever transport its network allows and is answered on
	// the same one. That is libreswan's `enable-tcp=fallback` without a mode to
	// choose.
	TCP bool

	// AssignAddr, if set, is called during IKE_AUTH to allocate internal tunnel
	// address(es) for a connecting client (CP config mode). It is told which
	// families the initiator's CFG_REQUEST actually named and must allocate only
	// those; a zero Assignment means no address is assigned (the Child SA is
	// still created).
	AssignAddr func(AddressRequest) (Assignment, error)
	// ReleaseAddr, if set, reclaims the assignment when the SA is torn down.
	ReleaseAddr func(Assignment)

	// IPTFSRate, when positive, makes every AGGFRAG Child SA transmit at that
	// many bytes per second regardless of load. It is the traffic-flow
	// confidentiality half of RFC 9347 and it costs that bandwidth
	// continuously, idle or not, which is why it is a number rather than a
	// flag: the operator chooses what they will spend.
	IPTFSRate int
	// IPTFS permits AGGFRAG (RFC 9347) on Child SAs whose client asks for it.
	// The responder never initiates it: USE_AGGFRAG is only agreed when both
	// peers send the notify, so this gates the echo, not the offer.
	IPTFS bool

	// DataPath, if set, receives Child SA lifecycle events so a data plane can
	// route ESP traffic.
	DataPath DataPath

	// Logger is optional; defaults to the standard logger.
	Logger *vlog.Logger

	// OnChildSA is invoked when a Child SA is established (in addition to
	// DataPath). Useful for tests and logging.
	OnChildSA func(sa *IKESA, child *ChildSA)
}

// DataPath is the interface the IKE layer uses to inform a data plane about
// Child SA lifecycle. The dataplane package provides a concrete implementation.
type DataPath interface {
	AddChild(sa *IKESA, child *ChildSA)
	RemoveChild(sa *IKESA, child *ChildSA)
}

// Server is a userspace IKEv2 responder with NAT-T support.
type Server struct {
	cfg Config
	log *vlog.Logger

	tr *transport

	// gate bounds unauthenticated work, and cookies is the protocol's own
	// stronger answer to the same problem -- see cookie.go.
	gate    *dataplane.Gate
	cookies *cookieJar

	// serverCred is the certificate credential the server signs its AUTH with
	// when a client authenticates by certificate (built from cfg.ServerCert).
	serverCred *certCredential

	mu       sync.RWMutex
	byRSPI   map[uint64]*IKESA
	byRemote map[string]*IKESA
	closing  bool
}

// NewServer creates a server from cfg.
func NewServer(cfg Config) (*Server, error) {
	if len(cfg.PSK) == 0 && cfg.ServerCert == nil {
		return nil, fmt.Errorf("ike: a PSK or ServerCert is required")
	}
	if cfg.LocalID.Type == 0 {
		return nil, fmt.Errorf("ike: LocalID is required")
	}
	var serverCred *certCredential
	if cfg.ServerCert != nil {
		cred, err := credentialFromTLS(cfg.ServerCert)
		if err != nil {
			return nil, fmt.Errorf("ike: server certificate: %w", err)
		}
		serverCred = cred
	}
	if cfg.Logger == nil {
		cfg.Logger = vlog.Text(os.Stderr)
	}
	if cfg.ListenIP == "" {
		cfg.ListenIP = "0.0.0.0"
	}
	if cfg.Port500 == 0 {
		cfg.Port500 = 500
	}
	if cfg.Port4500 == 0 {
		cfg.Port4500 = 4500
	}
	if len(cfg.LocalTS) == 0 {
		cfg.LocalTS = []payload.TrafficSelector{allTrafficV4(), allTrafficV6()}
	}
	if len(cfg.RemoteTS) == 0 {
		cfg.RemoteTS = []payload.TrafficSelector{allTrafficV4(), allTrafficV6()}
	}

	// Bind the sockets eagerly so a returned server is already listening: this
	// surfaces bind errors (port in use, privilege) to the caller immediately,
	// and removes the readiness race a lazy bind in ListenAndServe would create
	// (a client could send to an unbound port and get ECONNREFUSED).
	ip := net.ParseIP(cfg.ListenIP)
	if ip == nil {
		return nil, fmt.Errorf("ike: invalid ListenIP %q", cfg.ListenIP)
	}
	c500, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: cfg.Port500})
	if err != nil {
		return nil, fmt.Errorf("ike: bind :%d: %w", cfg.Port500, err)
	}
	c4500, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: cfg.Port4500})
	if err != nil {
		c500.Close()
		return nil, fmt.Errorf("ike: bind :%d: %w", cfg.Port4500, err)
	}

	s := &Server{
		cfg:        cfg,
		log:        cfg.Logger,
		gate:       dataplane.NewGate(dataplane.AdmissionConfig{}),
		cookies:    newCookieJar(),
		serverCred: serverCred,
		byRSPI:     make(map[uint64]*IKESA),
		byRemote:   make(map[string]*IKESA),
	}
	s.tr = &transport{
		conn500:    dataplane.NewPacketConn(c500),
		conn4500:   dataplane.NewPacketConn(c4500),
		onESP:      s.handleESP,
		onESPBatch: s.handleESPBatch,
	}
	if cfg.TCP {
		// Bound here rather than in ListenAndServe for the same reason the UDP
		// sockets are: a returned server is already listening, so a bind error
		// reaches the caller instead of a client.
		ln, lerr := net.Listen("tcp", net.JoinHostPort(cfg.ListenIP, strconv.Itoa(cfg.Port4500)))
		if lerr != nil {
			c500.Close()
			c4500.Close()
			return nil, fmt.Errorf("ike: bind tcp :%d: %w", cfg.Port4500, lerr)
		}
		s.tr.tcpLn = ln
	}
	s.log.Printf("ikev2: listening on %s (IKE :%d, NAT-T/ESP :%d%s)",
		cfg.ListenIP, cfg.Port500, cfg.Port4500, tcpNote(cfg.TCP, cfg.Port4500))
	return s, nil
}

// Assignment is the set of internal addresses handed to a client via the
// Configuration Payload. Any field may be zero: an IPv4-only server fills IP4 +
// Netmask, a dual-stack server fills IP6 + Prefix6 as well, and DNS may carry
// resolvers of either family.
// AddressRequest names the address families an initiator's CFG_REQUEST asked
// for, so the responder allocates those and no others.
//
// It exists because "allocate both, always" is legal and still breaks a peer.
// RFC 7296 section 2.19 permits the responder to "send other attributes that
// were not included in CP(CFG_REQUEST)", so veepin handing an IPv6 lease to a
// client that asked only for IPv4 violates nothing -- and libreswan, which asks
// only for INTERNAL_IP4_ADDRESS, took the address it never requested, built its
// child selectors from it, and then rejected the responder's echo of its own
// traffic selectors:
//
//	selectors: fd00:10:10::2/128 -> 10.10.10.0/24
//	CHILD SA failed: TS_UNACCEPTABLE
//
// strongSwan asks for both families, so no cell in the matrix could see it. The
// same over-assignment also leaked one IPv6 lease per IPv4-only client for as
// long as the server ran.
type AddressRequest struct {
	IP4 bool
	IP6 bool
}

type Assignment struct {
	IP4     net.IP // assigned internal IPv4 address, or nil
	Netmask net.IP // IPv4 netmask for IP4
	IP6     net.IP // assigned internal IPv6 address, or nil
	Prefix6 int    // IPv6 prefix length for IP6
	DNS     []net.IP
}

func allTrafficV4() payload.TrafficSelector {
	return payload.TrafficSelector{
		Type:       payload.TSIPv4AddrRange,
		IPProtocol: payload.IPProtoAny,
		StartPort:  0,
		EndPort:    65535,
		StartAddr:  net.IPv4zero.To4(),
		EndAddr:    net.IP{255, 255, 255, 255},
	}
}

// allTrafficV6 is the IPv6 counterpart of allTrafficV4: every IPv6 address,
// every port, every protocol (::/0 as a TS range).
func allTrafficV6() payload.TrafficSelector {
	return payload.TrafficSelector{
		Type:       payload.TSIPv6AddrRange,
		IPProtocol: payload.IPProtoAny,
		StartPort:  0,
		EndPort:    65535,
		StartAddr:  net.IPv6zero,
		EndAddr: net.IP{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		},
	}
}

// ListenAndServe processes messages on the sockets bound by NewServer until
// Close. It blocks until the server is closed.
func (s *Server) ListenAndServe() error {
	if s.tr == nil {
		return fmt.Errorf("ike: server is closed")
	}
	s.tr.serve(s.handlePacket, s.isClosing)
	return nil
}

func (s *Server) isClosing() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.closing
}

// Close stops the server.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closing = true
	s.mu.Unlock()
	if s.tr != nil {
		s.tr.close()
	}
	return nil
}

// handleESP forwards inbound ESP datagrams (port 4500) to the data plane, along
// with the UDP source address so replies can be sent back to the peer's actual
// ESP socket (which differs from its IKE port for a road-warrior client).
func (s *Server) handleESP(esp []byte, from *net.UDPAddr) {
	if dp, ok := s.cfg.DataPath.(espReceiver); ok {
		dp.HandleESP(esp, from)
	}
}

// handleESPBatch hands one read batch's ESP datagrams to the data path at
// once, so it can coalesce inbound TCP (GRO); a data path without the batch
// surface gets them one at a time.
func (s *Server) handleESPBatch(esp [][]byte, froms []*net.UDPAddr) {
	if dp, ok := s.cfg.DataPath.(espBatchReceiver); ok {
		dp.HandleESPBatch(esp, froms)
		return
	}
	for i, pkt := range esp {
		s.handleESP(pkt, froms[i])
	}
}

type espReceiver interface {
	HandleESP(esp []byte, from *net.UDPAddr)
}

type espBatchReceiver interface {
	HandleESPBatch(esp [][]byte, froms []*net.UDPAddr)
}

// peerAddrUpdater, if implemented by the DataPath, is told when a peer's
// transport address changes via MOBIKE UPDATE_SA_ADDRESSES, so ESP return
// traffic follows the move at once rather than waiting for the first inbound
// ESP datagram from the new address.
type peerAddrUpdater interface {
	UpdatePeerAddr(sa *IKESA, addr *net.UDPAddr)
}

// SetDataPath attaches a data plane after construction (used by the daemon so
// the pump's send function can reference the server's transport).
func (s *Server) SetDataPath(dp DataPath) {
	s.cfg.DataPath = dp
}

// SendESP transmits an encapsulated ESP datagram to a peer on the NAT-T socket.
// It matches the dataplane.Sender signature so a Pump can send through the
// server's own socket. In this userspace build ESP always rides UDP port 4500,
// so whether NAT-T encapsulation was negotiated makes no difference here; the
// Child SA still records it (ChildSA.UDPEncap) because the handshake needs it.
func (s *Server) SendESP(esp []byte, to *net.UDPAddr) {
	if s.tr == nil || to == nil {
		return
	}
	if err := s.tr.sendESP(esp, to); err != nil {
		s.log.Warnf("ikev2: ESP send error: %v", err)
	}
}

// SendESPBatch transmits a burst of encapsulated ESP datagrams for one peer —
// one sendmmsg on the NAT-T socket, or one write of several frames on a TCP
// stream. It matches the pump's batch-sender signature; the GSO egress path
// produces the bursts.
func (s *Server) SendESPBatch(esp [][]byte, to *net.UDPAddr) {
	if s.tr == nil || to == nil {
		return
	}
	if err := s.tr.sendESPBatch(esp, to); err != nil {
		s.log.Warnf("ikev2: ESP batch send error: %v", err)
	}
}

// liveStreams reports how many RFC 8229 streams the server currently holds. It
// is the cheapest way for a test to tell a TCP-encapsulated session from one
// that quietly fell back to the UDP sockets, which stay bound either way.
func (s *Server) liveStreams() int {
	if s.tr == nil {
		return 0
	}
	s.tr.smu.RLock()
	defer s.tr.smu.RUnlock()
	return len(s.tr.streams)
}

// udpEncap reports whether a Child SA's ESP will be UDP-encapsulated. Over a
// TCP stream it never is -- ESP is length-prefixed on the same connection -- and
// saying otherwise puts "udpencap=true" in the line an operator reads to find
// out which transport carried the session.
func (s *Server) udpEncap(sa *IKESA, remote *net.UDPAddr) bool {
	if s.tr != nil && s.tr.stream(remote) != nil {
		return false
	}
	return sa.NAT.natDetected() || sa.OnPort4500
}

// tcpNote renders the TCP half of the listening banner, so an operator can see
// from one line whether RFC 8229 encapsulation is actually accepted.
func tcpNote(on bool, port int) string {
	if !on {
		return ""
	}
	return fmt.Sprintf(", TCP :%d", port)
}

// send transmits an IKE message to a peer on the correct port.
func (s *Server) send(pkt []byte, remote *net.UDPAddr, on4500 bool) {
	if err := s.tr.sendIKE(pkt, remote, on4500); err != nil {
		s.log.Warnf("ikev2: send error: %v", err)
	}
}

func (s *Server) lookupByRSPI(rspi uint64) *IKESA {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byRSPI[rspi]
}

func (s *Server) storeSA(sa *IKESA) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byRSPI[sa.ResponderSPI] = sa
	if sa.RemoteAddr != nil {
		s.byRemote[sa.RemoteAddr.String()] = sa
	}
}

func (s *Server) deleteSA(sa *IKESA) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byRSPI, sa.ResponderSPI)
	// Only drop the by-remote entry if it still points at this SA: an IKE SA
	// rekey leaves the old and new SAs sharing one remote address, and the new
	// SA has already claimed the slot, so deleting the retired old SA must not
	// evict its successor.
	if sa.RemoteAddr != nil && s.byRemote[sa.RemoteAddr.String()] == sa {
		delete(s.byRemote, sa.RemoteAddr.String())
	}
	if s.cfg.ReleaseAddr != nil && (sa.ClientIP != nil || sa.ClientIP6 != nil) {
		s.cfg.ReleaseAddr(sa.assigned)
	}
}

// handlePacket is the top-level IKE ingress: parse the header, route by
// exchange. on4500 indicates the message arrived on the NAT-T port.
func (s *Server) handlePacket(pkt []byte, remote *net.UDPAddr, on4500 bool) {
	if len(pkt) < payload.HeaderLen {
		return
	}
	hdr, err := payload.ParseHeader(pkt)
	if err != nil {
		s.log.Printf("ikev2: bad header from %s: %v", remote, err)
		return
	}
	if hdr.Version>>4 != 2 {
		return
	}
	switch hdr.ExchangeType {
	case payload.IKE_SA_INIT:
		s.handleIKESAInit(pkt, hdr, remote, on4500)
	case payload.IKE_AUTH:
		s.handleSecured(pkt, hdr, remote, payload.IKE_AUTH, on4500)
	case payload.IKE_INTERMEDIATE:
		s.handleSecured(pkt, hdr, remote, payload.IKE_INTERMEDIATE, on4500)
	case payload.CREATE_CHILD_SA:
		s.handleSecured(pkt, hdr, remote, payload.CREATE_CHILD_SA, on4500)
	case payload.INFORMATIONAL:
		s.handleSecured(pkt, hdr, remote, payload.INFORMATIONAL, on4500)
	default:
		s.log.Printf("ikev2: unsupported exchange %s from %s", hdr.ExchangeType, remote)
	}
}
