package ike

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/enterprisevpn/internal/engine/dataplane"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/enterprisevpn/internal/engine/internal/cryptoutil"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/enterprisevpn/internal/engine/internal/ikev2/aggfrag"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/enterprisevpn/internal/engine/internal/ikev2/eap"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/enterprisevpn/internal/engine/internal/ikev2/esp"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/enterprisevpn/internal/engine/internal/ikev2/payload"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/enterprisevpn/internal/engine/internal/ikev2/transform"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/enterprisevpn/internal/engine/internal/vlog"
)

// ErrAuthFailed indicates the peer's authentication could not be verified —
// typically a wrong PSK or EAP password. Callers can errors.Is-check it to
// distinguish credential failures from transport/negotiation failures.
var ErrAuthFailed = errors.New("authentication failed")

// errNotAttached is returned by a control exchange (DPD, rekey) invoked before
// Attach put the client into post-handshake control mode.
var errNotAttached = errors.New("ike: client not attached for control exchanges")

// ClientConfig configures an IKEv2 client (initiator).
type ClientConfig struct {
	DialContext func(context.Context, string, string) (net.Conn, error)
	// ServerHost is the VPN server address (IP or hostname). Port defaults to
	// 500 for IKE; NAT-T floats to 4500 automatically.
	ServerHost string
	// ServerPort is the IKE port (default 500).
	ServerPort int
	// NATTPort is the port IKE floats to and ESP rides on (default 4500). It is
	// configurable only so tests can use an ephemeral port; production is 4500.
	NATTPort int

	// PSK authenticates the server (and the client too, unless EAP is used).
	PSK []byte
	// LocalID is the identity this client presents (IDi).
	LocalID Identity
	// RemoteID, if set, is checked against the server's IDr.
	RemoteID *Identity

	// EAPUsername/EAPPassword, if set, switch client authentication to
	// EAP-MSCHAPv2 (the server still authenticates itself with the PSK).
	EAPUsername string
	EAPPassword string

	// ClientCert, if set, authenticates the client with an X.509 certificate
	// (RFC 7427 digital signature, or the legacy RSA method against a peer that
	// does not offer RFC 7427) instead of the PSK. It takes precedence over PSK
	// but not over EAP.
	ClientCert *tls.Certificate
	// CARoots verifies the server's certificate when ClientCert is set. A nil
	// pool falls back to the host's system roots.
	CARoots *x509.CertPool

	// PostQuantum offers ML-KEM-768 as an additional key exchange (RFC 9370),
	// carried in an IKE_INTERMEDIATE exchange (RFC 9242) between IKE_SA_INIT and
	// IKE_AUTH. The result is hybrid: the classical group still runs and still
	// contributes, so a flaw in either one alone is not enough to recover the
	// keys. A server that does not offer it is not an error — the handshake
	// simply proceeds classically.
	PostQuantum bool

	// PostQuantumAuth additionally requires the responder to authenticate with
	// an ML-DSA certificate, and refuses an RSA or ECDSA one. It is what the
	// pq-ikev2 name sets, alongside PostQuantum.
	//
	// It says nothing about PSK: a pre-shared key is symmetric and is not broken
	// by a quantum adversary, which is the premise RFC 8784 rests on.
	PostQuantumAuth bool

	// IPTFS enables AGGFRAG aggregation and fragmentation (RFC 9347) for the
	// Child SA. When set, USE_AGGFRAG is advertised in IKE_AUTH.
	IPTFS bool
	// IPTFSRate is the constant-rate transmission target in bytes/sec. Zero
	// means aggregation-only.
	IPTFSRate int

	// TCP carries IKE and ESP over one TCP connection to the NAT-T port instead
	// of UDP (RFC 8229, updated by RFC 9329), for a network that blocks UDP.
	// There is no port-500 phase and no NAT-T float: the whole exchange is on
	// the stream from the first octet. See tcpstream.go.
	TCP bool

	Logger *vlog.Logger
}

// ClientResult holds the outcome of a successful handshake: the assigned
// internal configuration and the negotiated Child SA keys/parameters needed to
// run the data path.
type ClientResult struct {
	AssignedIP  net.IP
	Netmask     net.IP
	AssignedIP6 net.IP // internal IPv6 address (dual-stack), or nil
	Prefix6     int    // IPv6 prefix length for AssignedIP6
	DNS         []net.IP
	ServerAddr  *net.UDPAddr // where ESP is sent (port 4500 under NAT-T)
	UDPEncap    bool
	InboundSPI  uint32 // our SPI (server sends ESP to this)
	OutboundSPI uint32 // server's SPI (we send ESP to this)
	Suite       ESPSuite
	EncKeyOut   []byte // initiator->responder encryption key (we encrypt with this)
	IntegKeyOut []byte
	EncKeyIn    []byte // responder->initiator (we decrypt with this)
	IntegKeyIn  []byte
	// AggFrag is true when both peers agreed USE_AGGFRAG, so the Child SA
	// carries RFC 9347 AGGFRAG payloads instead of plain inner IP packets.
	AggFrag bool
	// AggFragFlags is what the PEER requires of us, from its USE_AGGFRAG
	// notify -- not what we asked of it. Its one flag that matters to a sender
	// is Don't Fragment: a peer that set it cannot reassemble, so every inner
	// packet must go in a single data block.
	AggFragFlags aggfrag.Flags
	// IPTFSRate, when positive, transmits at that many bytes per second
	// regardless of offered load. Copied from the config rather than
	// negotiated: RFC 9347 has no field for it, and there is nothing to
	// negotiate -- a constant-rate sender is indistinguishable to the receiver
	// from one that happens to be busy.
	IPTFSRate int
}

// Client is an IKEv2 initiator. It performs the handshake and exposes the
// negotiated Child SA so a data-plane pump can move traffic. One Client manages
// a single IKE SA.
type Client struct {
	cfg  ClientConfig
	log  *vlog.Logger
	conn *net.UDPConn
	// tcp is set instead of conn when cfg.TCP is on. The two are exclusive:
	// exactly one of them carries this SA, and every accessor below picks.
	tcp *TCPStream

	spiI, spiR uint64
	suite      Suite
	dh         cryptoutil.DHGroup
	ni, nr     []byte
	keys       SAKeys
	saInitReq  []byte
	saInitResp []byte
	sendMsgID  uint32
	on4500     bool // true once floated to NAT-T port 4500 (IKE needs the marker)

	// mobike is true once the server confirmed MOBIKE_SUPPORTED in IKE_AUTH,
	// which is the precondition for Roam.
	mobike bool

	// peerIntermediate records that the responder advertised
	// INTERMEDIATE_EXCHANGE_SUPPORTED. It is necessary but not sufficient: the
	// exchange only runs when an ADDKE method was also negotiated.
	peerIntermediate bool
	// addkeGroup is the additional key exchange method the responder accepted in
	// the ADDKE1 transform (RFC 9370), or 0 if none. Non-zero is what actually
	// triggers the IKE_INTERMEDIATE exchange.
	addkeGroup uint16
	// intAuthI / intAuthR are the RFC 9242 section 3.3 chains over the
	// IKE_INTERMEDIATE messages in each direction.
	intAuthI []byte
	intAuthR []byte
	// authMsgID is the message ID of the first IKE_AUTH request. It is 1 for a
	// plain handshake, but each IKE_INTERMEDIATE exchange consumes an ID first
	// (RFC 9242 section 3.2), so IKE_AUTH cannot simply hardcode 1 — reusing an
	// ID the responder has already answered gets the request dropped as a replay.
	authMsgID uint32

	// frag is true once the server confirmed IKE_FRAGMENTATION_SUPPORTED in
	// IKE_SA_INIT; fragReasm reassembles any fragmented responses it then sends.
	// We advertise support and reassemble inbound fragments but never fragment
	// our own requests.
	frag      bool
	fragReasm fragReassembler

	result *ClientResult

	// Certificate authentication (set when cfg.ClientCert != nil). certCred is
	// the local credential we sign AUTH with; caRoots verifies the server's
	// certificate; peerSigHashes is the server's advertised RFC 7427 hash list.
	certCred      *certCredential
	caRoots       *x509.CertPool
	peerSigHashes []uint16

	serverIDBody []byte // captured IDr body (for EAP final AUTH verification)

	mu     sync.Mutex
	closed bool

	// Post-handshake control channel. Once the data path owns socket reads, it
	// can no longer read IKE responses inline, so it delivers received IKE
	// datagrams here and the control exchanges (DPD, rekey) read from inbox
	// instead of the socket. exchMu serializes every initiator-driven exchange
	// (DPD, rekey, MOBIKE roam) so their message IDs never interleave.
	exchMu   sync.Mutex
	attached atomic.Bool
	inbox    chan []byte
}

// NewClient creates an IKEv2 client from cfg.
func NewClient(cfg ClientConfig) *Client {
	if cfg.ServerPort == 0 {
		cfg.ServerPort = 500
	}
	if cfg.NATTPort == 0 {
		cfg.NATTPort = 4500
	}
	logger := cfg.Logger
	if logger == nil {
		logger = vlog.Text(os.Stderr)
	}
	c := &Client{cfg: cfg, log: logger}
	if cfg.ClientCert != nil {
		cred, err := credentialFromTLS(cfg.ClientCert)
		if err != nil {
			// Defer the error to Connect so NewClient stays infallible; a nil
			// certCred with a non-nil ClientCert is the signal.
			logger.Printf("ikev2 client: invalid client certificate: %v", err)
		} else {
			c.certCred = cred
		}
		c.caRoots = cfg.CARoots
	}
	return c
}

// Connect performs IKE_SA_INIT and IKE_AUTH (PSK or EAP), returning the
// negotiated configuration and Child SA on success.
func (c *Client) Connect() (*ClientResult, error) {
	if err := c.dial(); err != nil {
		return nil, err
	}
	if err := c.setReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		c.closeConn()
		return nil, fmt.Errorf("set read deadline: %w", err)
	}

	if err := c.saInit(); err != nil {
		c.closeConn()
		return nil, fmt.Errorf("IKE_SA_INIT: %w", err)
	}
	c.log.Printf("ikev2 client: IKE_SA_INIT complete")

	// The additional key exchange runs only when the responder actually accepted
	// an ADDKE method. Support for the exchange alone is not enough: RFC 9242
	// leaves IKE_INTERMEDIATE with nothing to carry, and sending it anyway
	// stalls the handshake against a responder that has no reason to answer.
	c.sendMsgID = 1 // IKE_SA_INIT was 0

	// Float to the NAT-T port: IKE_AUTH and ESP both run on 4500 over one socket,
	// as RFC 3948 requires. Sharing the socket is what lets a standards-compliant
	// responder (e.g. strongSwan) send return ESP to our IKE source port.
	//
	// This must happen before IKE_INTERMEDIATE, not after. RFC 7296 section 2.23
	// switches *every* message after IKE_SA_INIT to 4500, and an intermediate
	// exchange left on 500 keeps the responder's SA pinned to the pre-float
	// port: strongSwan then sends return ESP to a socket we have already closed
	// and the tunnel comes up but carries nothing in that direction.
	if !c.cfg.TCP {
		if err := c.floatToNATT(); err != nil {
			c.Close()
			return nil, fmt.Errorf("NAT-T float: %w", err)
		}
	}

	if c.addkeGroup != 0 {
		if err := c.sendIntermediateExchange(); err != nil {
			c.closeConn()
			return nil, fmt.Errorf("IKE_INTERMEDIATE: %w", err)
		}
		c.log.Printf("ikev2 client: IKE_INTERMEDIATE complete (ML-KEM-768)")
	}
	c.authMsgID = c.sendMsgID

	switch {
	case c.cfg.EAPUsername != "":
		if err := c.authEAP(); err != nil {
			c.closeConn()
			return nil, fmt.Errorf("IKE_AUTH (EAP): %w", err)
		}
	case c.cfg.ClientCert != nil:
		if c.certCred == nil {
			c.closeConn()
			return nil, fmt.Errorf("IKE_AUTH (cert): client certificate is invalid")
		}
		if err := c.authCert(); err != nil {
			c.closeConn()
			return nil, fmt.Errorf("IKE_AUTH (cert): %w", err)
		}
	default:
		if err := c.authPSK(); err != nil {
			c.closeConn()
			return nil, fmt.Errorf("IKE_AUTH (PSK): %w", err)
		}
	}
	c.log.Printf("ikev2 client: authenticated, assigned %v", c.result.AssignedIP)
	// Clear the handshake read deadline; the data path (which now shares this
	// socket via DataConn, or this stream via DataStream) does its own blocking
	// reads.
	_ = c.setReadDeadline(time.Time{})
	return c.result, nil
}

// dial opens the transport this SA will run on and publishes it under the lock,
// so a concurrent Close (used to abort an in-flight handshake) observes it.
//
// The two transports differ in more than the socket type. UDP starts on port
// 500 and floats to 4500 after IKE_SA_INIT; TCP is on 4500 from the first
// octet, because RFC 8229 section 3 has no port-500 phase and nothing to float.
func (c *Client) dial() error {
	var (
		conn *net.UDPConn
		tcp  *TCPStream
		err  error
	)
	if c.cfg.TCP {
		tcp, err = dialTCPStream(c.cfg.ServerHost, c.cfg.NATTPort, tcpDialTimeout, c.cfg.DialContext)
		if err != nil {
			return fmt.Errorf("dial server (tcp): %w", err)
		}
	} else {
		// JoinHostPort brackets an IPv6 literal, which a bare "%s:%d" would
		// render ambiguously (e.g. fd00::10:500).
		raddr, rerr := net.ResolveUDPAddr("udp", net.JoinHostPort(c.cfg.ServerHost, strconv.Itoa(c.cfg.ServerPort)))
		if rerr != nil {
			return fmt.Errorf("resolve server: %w", rerr)
		}
		if conn, err = net.DialUDP("udp", nil, raddr); err != nil {
			return fmt.Errorf("dial server: %w", err)
		}
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		if conn != nil {
			conn.Close()
		}
		if tcp != nil {
			tcp.Close()
		}
		return fmt.Errorf("client closed")
	}
	c.conn, c.tcp = conn, tcp
	// on4500 is deliberately left false for TCP. It gates the non-ESP marker on
	// the UDP write path only; appendTCPIKE writes the marker itself, because on
	// a stream it is present from the very first message rather than appearing
	// after a float.
	c.mu.Unlock()
	return nil
}

// tcpDialTimeout bounds the TCP connect. It matches the handshake read deadline
// below: a responder that will not answer within ten seconds is not going to.
const tcpDialTimeout = 10 * time.Second

// setReadDeadline, closeConn, localAddr and remoteAddr are the four places the
// rest of the client touches its transport as something other than "write a
// message" or "read a message". Each picks between the socket and the stream.
func (c *Client) setReadDeadline(t time.Time) error {
	if c.tcp != nil {
		return c.tcp.SetReadDeadline(t)
	}
	return c.conn.SetReadDeadline(t)
}

func (c *Client) closeConn() {
	if c.tcp != nil {
		c.tcp.Close()
		return
	}
	if c.conn != nil {
		c.conn.Close()
	}
}

func (c *Client) localAddr() *net.UDPAddr {
	if c.tcp != nil {
		return udpAddrOf(c.tcp.LocalAddr())
	}
	return c.conn.LocalAddr().(*net.UDPAddr)
}

func (c *Client) remoteAddr() *net.UDPAddr {
	if c.tcp != nil {
		return udpAddrOf(c.tcp.RemoteAddr())
	}
	return c.conn.RemoteAddr().(*net.UDPAddr)
}

// floatToNATT switches the IKE socket to the server's NAT-T port (4500) after
// IKE_SA_INIT. It re-dials (a new local port is fine: a NAT-T responder tracks
// the peer's current source address), so IKE_AUTH and the ESP data path share
// one socket on 4500.
func (c *Client) floatToNATT() error {
	srv := c.remoteAddr()
	nconn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: srv.IP, Port: c.cfg.NATTPort})
	if err != nil {
		return err
	}
	if err := nconn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		nconn.Close()
		return err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		nconn.Close()
		return fmt.Errorf("client closed")
	}
	old := c.conn
	c.conn = nconn
	c.on4500 = true
	c.mu.Unlock()
	old.Close()
	return nil
}

// writeIKE sends one IKE message, prefixing the 4-byte non-ESP marker once the
// socket has floated to 4500 (so the peer's ESP demux can tell IKE from ESP).
func (c *Client) writeIKE(pkt []byte) error {
	if c.tcp != nil {
		return c.tcp.WriteIKE(pkt)
	}
	if c.on4500 {
		framed := make([]byte, 4+len(pkt))
		copy(framed[4:], pkt)
		_, err := c.conn.Write(framed)
		return err
	}
	_, err := c.conn.Write(pkt)
	return err
}

// writeIKEAll sends every datagram of a protected message in fragment order. A
// partial send is a failed message: RFC 7383 reassembly needs all of them, and
// the peer's reassembler drops what it has when the next message ID arrives.
func (c *Client) writeIKEAll(pkts [][]byte) error {
	if len(pkts) > 1 {
		c.log.Printf("ikev2 client: fragmenting request into %d RFC 7383 fragments", len(pkts))
	}
	for _, p := range pkts {
		if err := c.writeIKE(p); err != nil {
			return err
		}
	}
	return nil
}

// DataConn returns the IKE socket (floated to 4500) for the data path to share
// for ESP, or nil when this SA runs over TCP. Ownership stays with the Client;
// Close closes it.
func (c *Client) DataConn() *net.UDPConn { return c.conn }

// DataStream returns the RFC 8229 stream for the data path to share for ESP, or
// nil when this SA runs over UDP. Exactly one of DataConn and DataStream is
// non-nil, and which one is what the caller branches its data path on.
func (c *Client) DataStream() *TCPStream { return c.tcp }

// --- IKE_SA_INIT ---

func (c *Client) saInit() error {
	c.spiI = newIKESPI()
	dh, err := transform.DH(payload.DH_CURVE25519)
	if err != nil {
		return err
	}
	c.dh = dh
	pub, err := dh.Generate()
	if err != nil {
		return err
	}
	c.ni = mustNonce(32)

	props := DefaultIKEProposals()
	if c.cfg.PostQuantum {
		// RFC 9370: ML-KEM-768 as the first (and only) additional key exchange,
		// alongside the classical group above. Hybrid by construction — the
		// classical DH still runs, so this cannot be worse than not offering it.
		// Every proposal carries it: the responder may pick any of them, and one
		// that omitted the transform would silently drop back to classical-only.
		for i := range props {
			props[i].Transforms = append(props[i].Transforms,
				payload.Transform{Type: payload.TransformADDKE1, ID: payload.MLKEM768})
		}
	}

	b := payload.NewBuilder()
	b.Add(payload.TypeSA, false, payload.MarshalSA(payload.SAPayload{Proposals: props}))
	b.Add(payload.TypeKE, false, payload.MarshalKE(payload.KEPayload{Group: payload.DH_CURVE25519, KeyData: pub}))
	b.Add(payload.TypeNonce, false, payload.MarshalNonce(c.ni))
	local := c.localAddr()
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: payload.NATDetectionSourceIP,
		Data: natDetectionHash(c.spiI, 0, local.IP, uint16(local.Port)),
	}))
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: payload.NATDetectionDestinationIP,
		Data: natDetectionHash(c.spiI, 0, net.IPv4zero, 0),
	}))
	// Advertise IKE fragmentation (RFC 7383) so a server set to always fragment
	// can deliver large protected responses as reassemblable SKF fragments.
	addFragSupported(b)
	// Advertise RFC 7427 signature hashes when we will authenticate with a
	// certificate, so the responder signs (and accepts) a Digital Signature.
	if c.certCred != nil {
		addSigHashNotify(b)
	}
	// Advertise IKE_INTERMEDIATE support (RFC 9242), but only when we have
	// something to put in it. An unconditional notify invites a responder to
	// expect an exchange we will never send.
	if c.cfg.PostQuantum {
		addIntermediateNotify(b)
	}
	chain := b.Bytes()

	hdr := payload.Header{
		InitiatorSPI: c.spiI, NextPayload: b.FirstType(), Version: 0x20,
		ExchangeType: payload.IKE_SA_INIT, Flags: payload.FlagInitiator, MessageID: 0,
		Length: uint32(payload.HeaderLen + len(chain)),
	}
	req := append(hdr.Marshal(nil), chain...)
	c.saInitReq = req
	if err := c.writeIKE(req); err != nil {
		return err
	}

	resp, err := c.readMessage()
	if err != nil {
		return err
	}
	c.saInitResp = append([]byte(nil), resp...)
	msg, err := payload.ParseMessage(resp)
	if err != nil {
		return err
	}
	if n := findNotifyError(msg); n != 0 {
		return fmt.Errorf("server rejected SA_INIT: notify %d", n)
	}
	c.spiR = msg.Header.ResponderSPI
	c.frag = findFragSupported(msg.Payloads)
	c.peerSigHashes = findSigHashes(msg.Payloads)
	c.peerIntermediate = hasIntermediateSupport(msg)

	saPay := msg.Find(payload.TypeSA)
	kePay := msg.Find(payload.TypeKE)
	noncePay := msg.Find(payload.TypeNonce)
	if saPay == nil || kePay == nil || noncePay == nil {
		return fmt.Errorf("response missing SA/KE/Nonce")
	}
	sa, err := payload.ParseSA(saPay.Body)
	if err != nil {
		return err
	}
	suite, _, err := SelectIKESuite(sa)
	if err != nil {
		return fmt.Errorf("cannot resolve negotiated suite: %w", err)
	}
	c.suite = suite

	// RFC 9370 section 2.1: the responder either echoes an ADDKE transform it
	// accepted, or omits it (equivalent to NONE) and no additional exchange
	// happens. Requiring the notify as well means we never start an exchange a
	// responder cannot answer.
	//
	// Read the transform off the *parsed* response, not off SelectIKESuite's
	// second return value: that one is a reconstruction listing only the four
	// classical transform types, so an ADDKE the responder did accept would
	// vanish on the way through it.
	if c.cfg.PostQuantum && c.peerIntermediate {
		for _, p := range sa.Proposals {
			if p.Protocol != payload.ProtoIKE {
				continue
			}
			if group, ok := SelectADDKE(p); ok {
				c.addkeGroup = group
			}
			break
		}
	}
	if c.cfg.PostQuantum && c.addkeGroup == 0 {
		c.log.Printf("ikev2 client: server declined the post-quantum key exchange; continuing with the classical group only")
	}

	ke, _ := payload.ParseKE(kePay.Body)
	shared, err := c.dh.ComputeSecret(ke.KeyData)
	if err != nil {
		return err
	}
	c.nr = payload.ParseNonce(noncePay.Body)

	_, keys := DeriveIKEKeys(suite.PRF, shared, c.ni, c.nr, c.spiI, c.spiR,
		suite.encKeyLen(), suite.integKeyLen())
	c.keys = keys
	return nil
}

// --- IKE_AUTH (PSK) ---

func (c *Client) authPSK() error {
	idBody := idPayloadBody(c.cfg.LocalID)
	authData := computePSKAuth(c.suite.PRF, c.cfg.PSK, c.saInitReq, c.nr, c.keys.SKpi, idBody, c.intAuth(c.authMsgID))

	inner, childOutSPI := c.buildAuthInner(idBody, &payload.AuthPayload{
		Method: payload.AuthSharedKeyMIC, Data: authData,
	})
	pkts, err := c.seal(payload.IKE_AUTH, c.authMsgID, inner.FirstType(), inner.Bytes())
	if err != nil {
		return err
	}
	if err := c.writeIKEAll(pkts); err != nil {
		return err
	}

	inners, err := c.recvInners()
	if err != nil {
		return err
	}
	// IKE_AUTH consumed message ID 1; the next initiator request (e.g. a MOBIKE
	// UPDATE_SA_ADDRESSES) is 2.
	c.sendMsgID = c.authMsgID + 1
	return c.finishAuth(inners, childOutSPI, c.cfg.PSK, false)
}

// --- IKE_AUTH (certificate) ---

// authCert authenticates the client with an X.509 certificate in one round trip
// (like PSK, but the AUTH payload is a signature rather than a MAC). It sends
// IDi, the certificate chain, a CERTREQ, and the signed AUTH, then verifies the
// server's certificate and AUTH from the response.
func (c *Client) authCert() error {
	idBody := idPayloadBody(c.cfg.LocalID)
	octets := AuthOctets(c.suite.PRF, c.saInitReq, c.nr, c.keys.SKpi, idBody, c.intAuth(c.authMsgID))
	method, authData, err := signAuth(c.certCred, octets, c.peerSigHashes)
	if err != nil {
		return err
	}

	inner, childOutSPI := c.buildCertAuthInner(idBody, method, authData)
	pkts, err := c.seal(payload.IKE_AUTH, c.authMsgID, inner.FirstType(), inner.Bytes())
	if err != nil {
		return err
	}
	if err := c.writeIKEAll(pkts); err != nil {
		return err
	}

	inners, err := c.recvInners()
	if err != nil {
		return err
	}
	c.sendMsgID = c.authMsgID + 1
	if err := c.verifyServerCertAuth(inners); err != nil {
		return err
	}
	return c.applyAuthResult(inners, childOutSPI)
}

// dualStackTS is the TSi/TSr set the client offers: every IPv4 and every IPv6
// address, so one Child SA can carry both families (the server narrows/echoes).
func dualStackTS() payload.TSPayload {
	return payload.TSPayload{Selectors: []payload.TrafficSelector{allTrafficV4(), allTrafficV6()}}
}

// dualStackCPRequest is the CFG_REQUEST asking the server to assign an internal
// address in each family plus DNS, so a dual-stack server hands back both.
func dualStackCPRequest() payload.CPPayload {
	return payload.CPPayload{Type: payload.CFGRequest, Attrs: []payload.CFGAttr{
		{Type: payload.CFGInternalIP4Address},
		{Type: payload.CFGInternalIP4Netmask},
		{Type: payload.CFGInternalIP4DNS},
		{Type: payload.CFGInternalIP6Address},
		{Type: payload.CFGInternalIP6DNS},
	}}
}

// buildCertAuthInner assembles the certificate IKE_AUTH inner payloads: IDi, the
// certificate chain (leaf first), a CERTREQ, the signed AUTH, then the same CP /
// Child SA / TS / MOBIKE payloads the PSK path sends.
func (c *Client) buildCertAuthInner(idBody []byte, method payload.AuthMethod, authData []byte) (*payload.Builder, uint32) {
	childOutSPI := newChildSPI()
	tsAll := dualStackTS()
	cpReq := dualStackCPRequest()

	b := payload.NewBuilder()
	b.Add(payload.TypeIDi, false, idBody)
	for _, der := range c.certCred.chain {
		b.Add(payload.TypeCERT, false, payload.MarshalCert(payload.CertPayload{
			Encoding: payload.CertX509Signature, Data: der,
		}))
	}
	// Empty CERTREQ CA field: "send a certificate from any CA you trust".
	b.Add(payload.TypeCERTREQ, false, payload.MarshalCertReq(payload.CertReqPayload{
		Encoding: payload.CertX509Signature,
	}))
	b.Add(payload.TypeAUTH, false, payload.MarshalAuth(payload.AuthPayload{Method: method, Data: authData}))
	b.Add(payload.TypeCP, false, payload.MarshalCP(cpReq))
	b.Add(payload.TypeSA, false, payload.MarshalSA(payload.SAPayload{Proposals: DefaultESPProposals(u32BE(childOutSPI))}))
	b.Add(payload.TypeTSi, false, payload.MarshalTS(tsAll))
	b.Add(payload.TypeTSr, false, payload.MarshalTS(tsAll))
	if c.tcp == nil {
		addMobikeSupported(b)
	}
	return b, childOutSPI
}

// verifyServerCertAuth verifies the responder's IDr, certificate chain and AUTH
// signature in a certificate-authenticated IKE_AUTH response.
func (c *Client) verifyServerCertAuth(inners []payload.RawPayload) error {
	idrPay := findInner(inners, payload.TypeIDr)
	authPay := findInner(inners, payload.TypeAUTH)
	if idrPay == nil || authPay == nil {
		return fmt.Errorf("ike: cert response missing IDr/AUTH")
	}
	idr, err := payload.ParseID(idrPay.Body)
	if err != nil {
		return err
	}
	if c.cfg.RemoteID != nil {
		if idr.Type != c.cfg.RemoteID.Type || string(idr.Data) != string(c.cfg.RemoteID.Data) {
			return fmt.Errorf("ike: server identity mismatch")
		}
	}

	certs := findAllInner(inners, payload.TypeCERT)
	if len(certs) == 0 {
		return fmt.Errorf("ike: server sent no certificate")
	}
	leafDER, intermediates, perr := parseCertChain(certs)
	if perr != nil {
		return perr
	}
	roots := c.caRoots
	if roots == nil {
		sys, serr := x509.SystemCertPool()
		if serr != nil {
			return fmt.Errorf("ike: no CA roots configured and system pool unavailable: %w", serr)
		}
		roots = sys
	}
	leaf, err := verifyPeerCertChain(leafDER, intermediates, roots)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAuthFailed, err)
	}
	if err := certMatchesID(leaf, idr); err != nil {
		return fmt.Errorf("%w: %v", ErrAuthFailed, err)
	}

	auth, err := payload.ParseAuth(authPay.Body)
	if err != nil {
		return err
	}
	idrBody := idPayloadBody(Identity{Type: idr.Type, Data: idr.Data})
	octets := AuthOctets(c.suite.PRF, c.saInitResp, c.ni, c.keys.SKpr, idrBody, c.intAuth(c.authMsgID))
	if c.cfg.PostQuantumAuth {
		if err := requirePostQuantumKey(leaf.PublicKey); err != nil {
			return fmt.Errorf("ike: the responder's certificate is not post-quantum: %w", err)
		}
	}
	if err := verifyAuth(leaf.PublicKey, auth.Method, octets, auth.Data); err != nil {
		return fmt.Errorf("%w: %v", ErrAuthFailed, err)
	}
	c.serverIDBody = idrBody
	return nil
}

// --- IKE_AUTH (EAP-MSCHAPv2) ---

func (c *Client) authEAP() error {
	idBody := idPayloadBody(c.cfg.LocalID)

	// Message 1: IDi + CP + SA + TS, no AUTH (signals EAP).
	inner, childOutSPI := c.buildAuthInner(idBody, nil)
	pkts, err := c.seal(payload.IKE_AUTH, c.authMsgID, inner.FirstType(), inner.Bytes())
	if err != nil {
		return err
	}
	if err := c.writeIKEAll(pkts); err != nil {
		return err
	}

	// Response: IDr + server AUTH + EAP challenge.
	inners, err := c.recvInners()
	if err != nil {
		return err
	}
	if err := c.verifyServerAuth(inners, c.cfg.PSK, false); err != nil {
		return err
	}
	eapPay := findInner(inners, payload.TypeEAP)
	if eapPay == nil {
		return fmt.Errorf("server did not start EAP")
	}
	eapReq, err := eap.Parse(eapPay.Body)
	if err != nil {
		return err
	}
	ch, ok := eap.ParseChallenge(eapReq.Data)
	if !ok {
		return fmt.Errorf("EAP request was not an MSCHAPv2 challenge")
	}

	// Message 2: MSCHAPv2 response.
	respData, msk := ch.BuildResponse(c.cfg.EAPUsername, c.cfg.EAPPassword)
	if err := c.sendEAP(c.authMsgID+1, eap.Packet{Code: eap.CodeResponse, Identifier: eapReq.Identifier, Type: eap.TypeMSCHAPv2, Data: respData}); err != nil {
		return err
	}
	inners, err = c.recvInners()
	if err != nil {
		return err
	}
	eapPay = findInner(inners, payload.TypeEAP)
	if eapPay == nil {
		return fmt.Errorf("no EAP success (bad password?)")
	}
	successReq, _ := eap.Parse(eapPay.Body)
	if successReq.Code == eap.CodeRequest && len(successReq.Data) > 0 && successReq.Data[0] == 4 {
		return fmt.Errorf("server rejected credentials: %w", ErrAuthFailed)
	}

	// Message 3: acknowledge success.
	if err := c.sendEAP(c.authMsgID+2, eap.Packet{Code: eap.CodeResponse, Identifier: successReq.Identifier, Type: eap.TypeMSCHAPv2, Data: eap.SuccessResponseData()}); err != nil {
		return err
	}
	inners, err = c.recvInners()
	if err != nil {
		return err
	}
	if eapPay = findInner(inners, payload.TypeEAP); eapPay != nil {
		if final, _ := eap.Parse(eapPay.Body); final.Code != eap.CodeSuccess {
			return fmt.Errorf("expected EAP-Success, got code %d", final.Code)
		}
	}

	// Message 4: final AUTH keyed by the MSK.
	octets := AuthOctets(c.suite.PRF, c.saInitReq, c.nr, c.keys.SKpi, idBody, c.intAuth(c.authMsgID))
	authData := PSKAuth(c.suite.PRF, msk, octets)
	b := payload.NewBuilder()
	b.Add(payload.TypeAUTH, false, payload.MarshalAuth(payload.AuthPayload{Method: payload.AuthSharedKeyMIC, Data: authData}))
	pkts, err = c.seal(payload.IKE_AUTH, c.authMsgID+3, b.FirstType(), b.Bytes())
	if err != nil {
		return err
	}
	if err := c.writeIKEAll(pkts); err != nil {
		return err
	}

	inners, err = c.recvInners()
	if err != nil {
		return err
	}
	// The EAP flow consumed four consecutive message IDs from the first IKE_AUTH.
	c.sendMsgID = c.authMsgID + 4
	return c.finishAuth(inners, childOutSPI, msk, true)
}

func (c *Client) sendEAP(msgID uint32, p eap.Packet) error {
	b := payload.NewBuilder()
	b.Add(payload.TypeEAP, false, p.Marshal())
	pkts, err := c.seal(payload.IKE_AUTH, msgID, b.FirstType(), b.Bytes())
	if err != nil {
		return err
	}
	return c.writeIKEAll(pkts)
}

// buildAuthInner assembles the IKE_AUTH inner payloads. If auth is nil the AUTH
// payload is omitted (EAP mode). Returns the builder and our chosen Child SPI.
func (c *Client) buildAuthInner(idBody []byte, auth *payload.AuthPayload) (*payload.Builder, uint32) {
	childOutSPI := newChildSPI()
	tsAll := dualStackTS()
	cpReq := dualStackCPRequest()

	b := payload.NewBuilder()
	b.Add(payload.TypeIDi, false, idBody)
	if auth != nil {
		b.Add(payload.TypeAUTH, false, payload.MarshalAuth(*auth))
	}
	b.Add(payload.TypeCP, false, payload.MarshalCP(cpReq))
	b.Add(payload.TypeSA, false, payload.MarshalSA(payload.SAPayload{Proposals: DefaultESPProposals(u32BE(childOutSPI))}))
	b.Add(payload.TypeTSi, false, payload.MarshalTS(tsAll))
	b.Add(payload.TypeTSr, false, payload.MarshalTS(tsAll))
	// Advertise MOBIKE (RFC 4555) so the server permits us to relocate this SA's
	// addresses later without a full re-handshake. Not over TCP: the stream is
	// the binding, so there is no address to relocate without reconnecting.
	if c.tcp == nil {
		addMobikeSupported(b)
	}
	if c.cfg.IPTFS {
		// USE_AGGFRAG (RFC 9347 section 3.1). Both peers must send it; if the
		// responder does not echo it the Child SA carries ordinary inner IP
		// packets and we fall back, exactly as the PostQuantum path does.
		//
		// The one-octet flags body is not optional. This used to send the
		// notify empty, which every veepin accepted and strongSwan refuses the
		// whole IKE_AUTH message over -- "invalid notify data length for
		// USE_AGGFRAG (0)", checked before it looks at anything else.
		b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
			Protocol: payload.ProtoNone, Type: payload.UseAggFrag,
			Data: aggfrag.OurFlags.NotifyData(),
		}))
	}
	return b, childOutSPI
}

// acceptAggFrag reads the responder's USE_AGGFRAG echo and reports whether the
// Child SA carries AGGFRAG payloads, along with the flags the peer requires.
//
// A malformed notify, or one requiring something unimplemented, turns AGGFRAG
// OFF rather than failing the handshake. That is RFC 9347 section 5.1's own
// instruction -- "the receiver SHOULD NOT enable use of AGGFRAG_PAYLOAD" -- and
// it is the safe direction: the Child SA is already established and carries
// plain inner IP perfectly well, whereas refusing it here would turn a
// negotiable option into a connection failure.
func (c *Client) acceptAggFrag(inners []payload.RawPayload) (bool, aggfrag.Flags) {
	n := findNotify(inners, payload.UseAggFrag)
	if n == nil {
		return false, 0
	}
	flags, err := aggfrag.ParseFlags(n.Data)
	if err != nil {
		c.log.Printf("ike: %v; not enabling AGGFRAG", err)
		return false, 0
	}
	if flags.Unsupported() {
		c.log.Printf("ike: peer requires AGGFRAG flags 0x%02x this does not implement; "+
			"not enabling AGGFRAG", byte(flags))
		return false, 0
	}
	return true, flags
}

// verifyServerAuth checks the responder's IDr and AUTH payload. On the EAP
// final message the IDr is not resent, so a previously captured IDr is reused.
func (c *Client) verifyServerAuth(inners []payload.RawPayload, key []byte, eapMSK bool) error {
	authPay := findInner(inners, payload.TypeAUTH)
	if authPay == nil {
		return fmt.Errorf("response missing AUTH")
	}
	auth, err := payload.ParseAuth(authPay.Body)
	if err != nil {
		return err
	}

	// Resolve the responder identity: from this message if present, else from
	// the one captured earlier (EAP final AUTH omits IDr).
	var peerIDBody []byte
	if idrPay := findInner(inners, payload.TypeIDr); idrPay != nil {
		idr, _ := payload.ParseID(idrPay.Body)
		if c.cfg.RemoteID != nil {
			if idr.Type != c.cfg.RemoteID.Type || string(idr.Data) != string(c.cfg.RemoteID.Data) {
				return fmt.Errorf("server identity mismatch")
			}
		}
		peerIDBody = idPayloadBody(Identity{Type: idr.Type, Data: idr.Data})
		c.serverIDBody = peerIDBody
	} else if c.serverIDBody != nil {
		peerIDBody = c.serverIDBody
	} else {
		return fmt.Errorf("response missing IDr")
	}

	if eapMSK {
		octets := AuthOctets(c.suite.PRF, c.saInitResp, c.ni, c.keys.SKpr, peerIDBody, c.intAuth(c.authMsgID))
		want := PSKAuth(c.suite.PRF, key, octets)
		if !equalBytes(want, auth.Data) {
			return fmt.Errorf("server AUTH (MSK) verification failed: %w", ErrAuthFailed)
		}
		return nil
	}
	if err := verifyPeerPSKAuth(c.suite.PRF, key, c.saInitResp, c.ni, c.keys.SKpr, peerIDBody, c.intAuth(c.authMsgID), auth.Data); err != nil {
		return fmt.Errorf("%w: %v", ErrAuthFailed, err)
	}
	return nil
}

// finishAuth verifies server AUTH (unless already done for EAP), captures the
// CP assignment and derives the Child SA.
func (c *Client) finishAuth(inners []payload.RawPayload, childOutSPI uint32, authKey []byte, eapMSK bool) error {
	if err := c.verifyServerAuth(inners, authKey, eapMSK); err != nil {
		return err
	}
	return c.applyAuthResult(inners, childOutSPI)
}

// applyAuthResult captures the negotiated configuration from a verified IKE_AUTH
// response: MOBIKE confirmation, the CP address assignment, and the Child SA. It
// runs after the server's AUTH has been checked by whichever method was used
// (PSK, EAP-MSK or certificate).
func (c *Client) applyAuthResult(inners []payload.RawPayload, childOutSPI uint32) error {
	// MOBIKE is enabled only if the server confirmed it (RFC 4555 3.1).
	c.mobike = findMobikeSupported(inners)

	res := &ClientResult{OutboundSPI: 0, InboundSPI: childOutSPI}

	// CP assignment.
	if cpPay := findInner(inners, payload.TypeCP); cpPay != nil {
		if cp, perr := payload.ParseCP(cpPay.Body); perr == nil {
			if v, ok := cp.AttrValue(payload.CFGInternalIP4Address); ok && len(v) == 4 {
				res.AssignedIP = net.IP(v).To4()
			}
			if v, ok := cp.AttrValue(payload.CFGInternalIP4Netmask); ok && len(v) == 4 {
				res.Netmask = net.IP(v).To4()
			}
			// INTERNAL_IP6_ADDRESS is 16 address octets + a 1-octet prefix length.
			if v, ok := cp.AttrValue(payload.CFGInternalIP6Address); ok && len(v) == 17 {
				res.AssignedIP6 = append(net.IP(nil), v[:16]...)
				res.Prefix6 = int(v[16])
			}
			for _, a := range cp.Attrs {
				switch {
				case a.Type == payload.CFGInternalIP4DNS && len(a.Value) == 4:
					res.DNS = append(res.DNS, net.IP(a.Value).To4())
				case a.Type == payload.CFGInternalIP6DNS && len(a.Value) == 16:
					res.DNS = append(res.DNS, append(net.IP(nil), a.Value...))
				}
			}
		}
	}
	if res.AssignedIP == nil && res.AssignedIP6 == nil {
		return fmt.Errorf("server did not assign an internal address")
	}

	// Child SA.
	saPay := findInner(inners, payload.TypeSA)
	if saPay == nil {
		return fmt.Errorf("no Child SA in response")
	}
	espSA, _ := payload.ParseSA(saPay.Body)
	es, _, serr := SelectESPSuite(espSA)
	if serr != nil {
		return fmt.Errorf("cannot resolve ESP suite: %w", serr)
	}
	res.Suite = es
	if len(espSA.Proposals) > 0 && len(espSA.Proposals[0].SPI) == 4 {
		res.OutboundSPI = beU32(espSA.Proposals[0].SPI)
	}

	// AGGFRAG is on only if the responder echoed USE_AGGFRAG. Assuming it from
	// our own request would put next-header 144 on the wire against a peer
	// expecting plain inner IP, and every packet would be dropped as malformed.
	if c.cfg.IPTFS {
		res.AggFrag, res.AggFragFlags = c.acceptAggFrag(inners)
		res.IPTFSRate = c.cfg.IPTFSRate
		if res.AggFrag {
			c.log.Printf("ike: AGGFRAG (RFC 9347) negotiated; ESP next header %d, peer flags 0x%02x",
				aggfrag.ESPNextHeader, byte(res.AggFragFlags))
		} else {
			c.log.Printf("ike: peer did not offer USE_AGGFRAG; falling back to plain ESP")
		}
	}

	// Derive Child keys (initiator perspective).
	encLen := es.Cipher.KeyLen()
	integLen := 0
	if es.Integ != nil {
		integLen = es.Integ.KeyLen
	}
	total := 2*encLen + 2*integLen
	km := DeriveChildKeys(c.suite.PRF, c.keys.SKd, nil, c.ni, c.nr, total)
	off := 0
	take := func(n int) []byte { b := km[off : off+n]; off += n; return b }
	res.EncKeyOut = take(encLen)
	if integLen > 0 {
		res.IntegKeyOut = take(integLen)
	}
	res.EncKeyIn = take(encLen)
	if integLen > 0 {
		res.IntegKeyIn = take(integLen)
	}

	// Server ESP endpoint: the NAT-T port the socket floated to (4500 in prod),
	// or the stream's remote end. Over TCP the address is identity rather than
	// a destination -- the stream is where ESP goes -- and ESP is
	// length-prefixed on it rather than UDP-encapsulated.
	srv := c.remoteAddr()
	res.ServerAddr = &net.UDPAddr{IP: srv.IP, Port: srv.Port}
	res.UDPEncap = c.tcp == nil

	c.result = res
	return nil
}

// --- MOBIKE (RFC 4555) ---

// MobikeEnabled reports whether MOBIKE was negotiated, i.e. whether Roam may be
// called. It is valid only after a successful Connect.
// MOBIKE is never enabled over TCP: the connection IS the address binding, so
// there is nothing to update -- an address change breaks the stream, and the
// answer is to reconnect rather than to send UPDATE_SA_ADDRESSES over a socket
// that no longer exists.
func (c *Client) MobikeEnabled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mobike && c.tcp == nil
}

// Roam relocates the IKE SA and its Child SAs to a fresh local address after
// the client's network changed (RFC 4555). It re-dials the NAT-T socket from a
// new local port and sends an UPDATE_SA_ADDRESSES INFORMATIONAL — with fresh
// NAT-detection hashes and a COOKIE2 the responder must echo — over the new
// socket. On success the client's data socket (DataConn) is the new one, so a
// caller sharing that socket for ESP must re-fetch it.
//
// Roam is for a caller driving the data path itself; it must not run
// concurrently with itself. It leaves the new socket without a read deadline,
// matching the socket state Connect leaves for the data path.
func (c *Client) Roam() error {
	// Serialize with DPD and rekey: all three consume initiator message IDs.
	c.exchMu.Lock()
	defer c.exchMu.Unlock()

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return fmt.Errorf("client closed")
	}
	if c.tcp != nil {
		c.mu.Unlock()
		return fmt.Errorf("ike: MOBIKE does not apply over TCP: the connection is the address binding, so a move needs a reconnect")
	}
	if !c.mobike {
		c.mu.Unlock()
		return fmt.Errorf("ike: MOBIKE was not negotiated")
	}
	srv := c.remoteAddr()
	c.mu.Unlock()

	// New socket from a fresh local port to the same server (a NAT-T responder
	// tracks the peer's current source address, so a new local port is fine).
	nconn, err := net.DialUDP("udp", nil, srv)
	if err != nil {
		return fmt.Errorf("ike: roam dial: %w", err)
	}
	if err := nconn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		nconn.Close()
		return err
	}

	// Publish the new socket so writeIKE/readMessage use it, keeping the old to
	// restore on failure.
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		nconn.Close()
		return fmt.Errorf("client closed")
	}
	old := c.conn
	c.conn = nconn
	c.mu.Unlock()

	if err := c.sendUpdateSAAddresses(srv); err != nil {
		c.mu.Lock()
		c.conn = old
		c.mu.Unlock()
		nconn.Close()
		return err
	}
	old.Close()
	_ = c.conn.SetReadDeadline(time.Time{})
	return nil
}

// sendUpdateSAAddresses performs the UPDATE_SA_ADDRESSES exchange over the
// (already-swapped) new socket and verifies the responder echoed our COOKIE2.
func (c *Client) sendUpdateSAAddresses(srv *net.UDPAddr) error {
	local := c.localAddr()
	cookie2 := mustNonce(16)

	b := payload.NewBuilder()
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: payload.UpdateSAAddresses,
	}))
	// Fresh NAT detection from the new local address to the same server.
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: payload.NATDetectionSourceIP,
		Data: natDetectionHash(c.spiI, c.spiR, local.IP, uint16(local.Port)),
	}))
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: payload.NATDetectionDestinationIP,
		Data: natDetectionHash(c.spiI, c.spiR, srv.IP, uint16(srv.Port)),
	}))
	// COOKIE2 return-routability probe; the responder must echo it.
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: payload.Cookie2, Data: cookie2,
	}))

	msgID := c.sendMsgID
	pkts, err := c.seal(payload.INFORMATIONAL, msgID, b.FirstType(), b.Bytes())
	if err != nil {
		return err
	}
	if err := c.writeIKEAll(pkts); err != nil {
		return fmt.Errorf("ike: roam send: %w", err)
	}

	inners, err := c.recvInners()
	if err != nil {
		return fmt.Errorf("ike: roam response: %w", err)
	}
	echo := findMobikeCookie2(inners)
	if echo == nil || !equalBytes(echo, cookie2) {
		return fmt.Errorf("ike: roam return-routability failed (COOKIE2 not echoed)")
	}
	c.sendMsgID = msgID + 1
	return nil
}

// findMobikeCookie2 returns the COOKIE2 data among inners, or nil.
func findMobikeCookie2(inners []payload.RawPayload) []byte {
	if n := findNotify(inners, payload.Cookie2); n != nil {
		return n.Data
	}
	return nil
}

// --- helpers ---

// seal builds the datagrams for one protected message: one, or several SKF
// fragments when the message would exceed fragmentThreshold and the peer
// advertised RFC 7383 support. Every returned datagram must be sent, in order.
func (c *Client) seal(ex payload.ExchangeType, msgID uint32, first payload.PayloadType, inner []byte) ([][]byte, error) {
	hdr := payload.Header{
		InitiatorSPI: c.spiI, ResponderSPI: c.spiR, Version: 0x20,
		ExchangeType: ex, Flags: payload.FlagInitiator, MessageID: msgID,
	}
	return sealMaybeFragment(hdr, c.suite, c.keys, dirInitiatorToResponder, first, inner, c.frag)
}

func (c *Client) recvInners() ([]payload.RawPayload, error) {
	return c.recvInnersFrom(c.readMessage)
}

// recvInnersFrom is recvInners with an explicit datagram source: the socket
// (c.readMessage) during the handshake and MOBIKE roam, or the delivered-inbox
// reader once the data path owns socket reads (DPD, rekey).
func (c *Client) recvInnersFrom(read func() ([]byte, error)) ([]payload.RawPayload, error) {
	// A fragmented response spans several datagrams (RFC 7383); loop reading and
	// reassembling until one complete message is in hand.
	for {
		raw, err := read()
		if err != nil {
			return nil, err
		}
		msg, err := payload.ParseMessage(raw)
		if err != nil {
			return nil, err
		}
		if n := findNotifyError(msg); n != 0 {
			return nil, fmt.Errorf("server error notify %d", n)
		}

		var first payload.PayloadType
		var inner []byte
		if skf := msg.Find(payload.TypeSKF); skf != nil {
			if !c.frag {
				return nil, fmt.Errorf("server sent an SKF fragment without negotiating fragmentation")
			}
			fragNum, total, fi, chunk, derr := decryptSKF(raw, *skf, c.suite, c.keys, dirResponderToInitiator)
			if derr != nil {
				return nil, derr
			}
			reasm, rfi, complete, rerr := c.fragReasm.add(msg.Header.MessageID, fragNum, total, fi, chunk)
			if rerr != nil {
				return nil, rerr
			}
			if !complete {
				continue // read the next fragment
			}
			inner, first = reasm, rfi
		} else {
			sk := msg.Find(payload.TypeSK)
			if sk == nil {
				return nil, fmt.Errorf("response has no SK payload")
			}
			fi, in, derr := decryptSK(raw, msg.Header, *sk, c.suite, c.keys, dirResponderToInitiator)
			if derr != nil {
				return nil, derr
			}
			first, inner = fi, in
		}

		inners, err := parseInnerPayloads(first, inner)
		if err != nil {
			return nil, err
		}
		// A rejection arrives as an encrypted (inner) error notify; surface
		// AUTHENTICATION_FAILED as ErrAuthFailed so callers can tell a bad
		// credential from a transport failure.
		if n := findInnerNotifyError(inners); n != 0 {
			if n == uint16(payload.AuthenticationFailed) {
				return nil, fmt.Errorf("server: notify %d: %w", n, ErrAuthFailed)
			}
			return nil, fmt.Errorf("server error notify %d", n)
		}
		return inners, nil
	}
}

// findInnerNotifyError returns the first error-class notify type (< 16384) among
// decrypted inner payloads, or 0 if none.
func findInnerNotifyError(inners []payload.RawPayload) uint16 {
	for _, p := range inners {
		if p.Type == payload.TypeNotify {
			n, err := payload.ParseNotify(p.Body)
			if err == nil && uint16(n.Type) < 16384 && n.Type != 0 {
				return uint16(n.Type)
			}
		}
	}
	return 0
}

// readMessage reads one UDP datagram, stripping the 4-byte non-ESP marker if
// present (NAT-T on port 4500).
func (c *Client) readMessage() ([]byte, error) {
	if c.tcp != nil {
		return c.tcp.ReadIKE()
	}
	buf := make([]byte, 65535)
	n, err := c.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	pkt := buf[:n]
	// Non-ESP marker: 4 zero octets prefixed to IKE on 4500.
	if len(pkt) >= 4 && pkt[0] == 0 && pkt[1] == 0 && pkt[2] == 0 && pkt[3] == 0 {
		pkt = pkt[4:]
	}
	return pkt, nil
}

// Close tears down the IKE SA socket. It is idempotent and may be called
// concurrently with an in-flight Connect to abort it (closing the socket
// unblocks Connect's blocked read).
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.tcp != nil {
		return c.tcp.Close()
	}
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// BuildTunnel converts the negotiated client Child SA into a dataplane.Tunnel
// ready for the pump. The client uses the initiator key directions: it encrypts
// outbound with the initiator->responder keys and decrypts inbound with the
// responder->initiator keys.
func (r *ClientResult) BuildTunnel() (dataplane.Tunnel, error) {
	if r.Suite.EncrID == 0 {
		return nil, fmt.Errorf("ike: client result has no negotiated cipher")
	}
	sa := &esp.SA{
		SPIOut: r.OutboundSPI, // server's inbound SPI (we send to it)
		SPIIn:  r.InboundSPI,  // our SPI (server sends to it)
		Out: esp.Transform{
			EncrID: r.Suite.EncrID, EncrKeyLn: r.Suite.EncrKeyLn, IntegID: r.Suite.IntegID,
			EncKey: r.EncKeyOut, IntegKey: r.IntegKeyOut,
		},
		In: esp.Transform{
			EncrID: r.Suite.EncrID, EncrKeyLn: r.Suite.EncrKeyLn, IntegID: r.Suite.IntegID,
			EncKey: r.EncKeyIn, IntegKey: r.IntegKeyIn,
		},
	}
	t := &espTunnel{
		espSA: sa,
		inSPI: r.InboundSPI,
		// Client side: everything leaving the local TUN belongs to the one server,
		// so this tunnel carries all destinations in both families.
		routes: append(defaultRoute(), defaultRoute6()...),
	}
	t.peer.Store(r.ServerAddr)
	if !r.AggFrag {
		return t, nil
	}
	af := newAggfragTunnel(t)
	if r.IPTFSRate > 0 {
		return newPacedTunnel(af, r.IPTFSRate, iptfsPayloadSize), nil
	}
	return af, nil
}

func mustNonce(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// findNotifyError returns the first error-class notify type (< 16384) in a
// message, or 0 if none.
func findNotifyError(msg *payload.Message) uint16 {
	for _, p := range msg.Payloads {
		if p.Type == payload.TypeNotify {
			n, err := payload.ParseNotify(p.Body)
			if err == nil && uint16(n.Type) < 16384 && n.Type != 0 {
				return uint16(n.Type)
			}
		}
	}
	return 0
}
