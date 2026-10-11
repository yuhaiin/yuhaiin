package sstp

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/debuglog"
	"github.com/xen0bit/veepin/internal/mschap"
	"github.com/xen0bit/veepin/internal/ppp"
	"github.com/xen0bit/veepin/internal/pqpolicy"
	"github.com/xen0bit/veepin/internal/sstp/wire"
	"github.com/xen0bit/veepin/internal/userdb"
	"github.com/xen0bit/veepin/internal/vlog"
)

// ServerConfig configures an SSTP responder and its userspace data path.
type ServerConfig struct {
	// Cert, Key are the server's TLS certificate and private key, PEM (required).
	// The certificate is what the crypto binding hashes, so it must be the one
	// clients connect to.
	Cert []byte
	Key  []byte

	// ListenIP is the local address to bind on; empty binds all interfaces.
	ListenIP string
	// ListenPort is the TCP port to accept clients on (default 443).
	ListenPort int

	// Pool is the internal address pool handed to clients, CIDR (default
	// 10.9.0.0/24). Its first host is the server's tunnel address.
	Pool string
	// DNS servers assigned to clients over IPCP.
	DNS []net.IP
	// Users maps a username to its password for MS-CHAPv2 authentication.
	Users map[string]string

	// Shape enables downstream traffic shaping: how much padded output each
	// inner flow is given before shaping stops for that flow, so it bounds what
	// shaping costs. A flow gets Shape/MTU padded packets whatever sizes it
	// carries. Zero, the default, disables it.
	//
	// It hides the size pattern of an inner TLS handshake, which otherwise
	// shows through as the size of the TLS record carrying it (see
	// dataplane/shape.go). Clients need no support for it — the padding is
	// RFC 1661 §5.1 PPP padding, which every conforming peer trims by the inner
	// IP header — so a stock Windows SSTP client benefits unmodified.
	// dataplane.DefaultShapeBytes is a reasonable value.
	Shape int

	// TUNName is the desired TUN interface name; empty lets the kernel pick.
	TUNName string
	// Logger receives progress logs; nil discards them.
	Logger *slog.Logger

	// PostQuantumOnly requires a post-quantum key exchange and ML-DSA
	// authentication, refusing anything less rather than negotiating down. It is
	// what the pq-sstp registry name sets; see internal/pqpolicy for the
	// contract and doc/pq-variants-plan.md for why it is a name rather than a
	// flag.
	PostQuantumOnly bool
}

// handshakeTimeout bounds the TLS/HTTP/SSTP/PPP negotiation before the tunnel is
// up; after that the connection carries data with no deadline.
const handshakeTimeout = 30 * time.Second

func (c *ServerConfig) validate() error {
	if len(c.Cert) == 0 || len(c.Key) == 0 {
		return errors.New("sstp: server certificate and key are required")
	}
	if len(c.Users) == 0 {
		return errors.New("sstp: at least one user is required")
	}
	return nil
}

// Server is a running SSTP responder. Unlike the datagram protocols it is
// connection-oriented: each client rides its own TLS/TCP connection, so the
// server accepts connections and serves one goroutine per client, all sharing one
// TUN. It owns the TUN but does not configure host networking.
type Server struct {
	tlsCfg        *tls.Config
	serverCertDER []byte
	pool          *dataplane.AddrPool
	gateway       net.IP
	dns           []net.IP
	users         map[string]string
	logger        *vlog.Logger
	gate          *dataplane.Gate
	// shaper pads outbound PPP frames so the TLS record carrying them says less
	// about the packet inside; nil disables shaping.
	//
	// One Shaper is safe to share across clients here precisely because tunLoop
	// is the single goroutine that consults it — the same single-owner rule the
	// pump relies on. Hanging one off each client would race.
	shaper *dataplane.Shaper

	listenAddr *net.TCPAddr
	tun        *dataplane.TUN
	listener   net.Listener

	mu      sync.Mutex
	clients map[uint32]*sstpClient // keyed by assigned inner IP

	closeOnce sync.Once
	closed    chan struct{}
}

// NewServer builds a server from cfg: it parses the certificate and pool and
// opens the TUN device. It does not bind the socket until ListenAndServe. Opening
// a TUN device requires CAP_NET_ADMIN.
func NewServer(cfg ServerConfig) (*Server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("sstp: server certificate: %w", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if cfg.PostQuantumOnly {
		// Before the TUN is opened and before anything binds: an operator who
		// pointed pq-sstp at their existing RSA certificate learns it here,
		// rather than from a listener that comes up and then refuses everyone.
		if err := pqpolicy.CheckCredential(cert); err != nil {
			return nil, err
		}
		pqpolicy.HardenTLS(tlsCfg)
	}

	poolCIDR := cfg.Pool
	if poolCIDR == "" {
		poolCIDR = "10.9.0.0/24"
	}
	pool, gateway, err := dataplane.NewAddrPool(poolCIDR)
	if err != nil {
		return nil, fmt.Errorf("sstp: pool: %w", err)
	}

	port := cfg.ListenPort
	if port == 0 {
		port = 443
	}
	listenIP := net.ParseIP(cfg.ListenIP)
	if cfg.ListenIP == "" {
		listenIP = net.IPv4zero
	}
	if listenIP == nil {
		return nil, fmt.Errorf("sstp: invalid listen IP %q", cfg.ListenIP)
	}

	logger := vlog.From(cfg.Logger)
	if cfg.Logger == nil {
		logger = vlog.Text(debuglog.Writer())
	}

	tun, err := dataplane.OpenTUN(cfg.TUNName)
	if err != nil {
		return nil, fmt.Errorf("sstp: open TUN: %w", err)
	}

	var shaper *dataplane.Shaper
	if cfg.Shape > 0 {
		shaper = dataplane.NewShaper(dataplane.ShapeConfig{Bytes: cfg.Shape})
		logger.Printf("sstp: downstream shaping on, %d bytes per flow", cfg.Shape)
	}

	return &Server{
		tlsCfg:        tlsCfg,
		gate:          dataplane.NewGate(dataplane.AdmissionConfig{}),
		shaper:        shaper,
		serverCertDER: cert.Certificate[0],
		pool:          pool,
		gateway:       gateway,
		dns:           cfg.DNS,
		users:         cfg.Users,
		logger:        logger,
		listenAddr:    &net.TCPAddr{IP: listenIP, Port: port},
		tun:           tun,
		clients:       make(map[uint32]*sstpClient),
		closed:        make(chan struct{}),
	}, nil
}

// TUNName is the interface the data path is bound to.
func (s *Server) TUNName() string { return s.tun.Name() }

// Gateway is the server's own tunnel-side address (the pool's first host).
func (s *Server) Gateway() net.IP { return s.gateway }

// Network is the tunnel subnet, for routing and NAT rules.
func (s *Server) Network() *net.IPNet { return s.pool.Network() }

// ListenAndServe binds the TLS listener, starts the TUN read loop, and serves
// clients until Close. It blocks.
func (s *Server) ListenAndServe() error {
	ln, err := tls.Listen("tcp", s.listenAddr.String(), s.tlsCfg)
	if err != nil {
		return fmt.Errorf("sstp: listen: %w", err)
	}
	s.listener = ln
	s.logger.Printf("sstp: listening on %s, gateway %s", s.listenAddr, s.gateway)

	go s.tunLoop()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return nil
			default:
				return fmt.Errorf("sstp: accept: %w", err)
			}
		}
		// A TLS handshake plus the PPP negotiation behind it is real work done
		// for a peer that has not authenticated. Bounding it here, at accept,
		// covers the whole cost rather than only the part after TLS completes.
		if r := s.gate.Admit(conn.RemoteAddr()); r != dataplane.Admitted {
			s.logger.Warnf("sstp: refusing connection from %s: %v", conn.RemoteAddr(), r)
			_ = conn.Close()
			continue
		}
		go func(c *tls.Conn) {
			defer s.gate.Done()
			s.handleConn(c)
		}(conn.(*tls.Conn))
	}
}

// tunLoop reads packets off the TUN and routes each to the client that owns its
// destination address, sealing it as a PPP frame in an SSTP data packet.
func (s *Server) tunLoop() {
	buf := make([]byte, 65535)
	for {
		n, err := s.tun.Read(buf)
		if err != nil {
			return
		}
		dst, ok := ipv4Dst(buf[:n])
		if !ok {
			continue
		}
		s.mu.Lock()
		cl := s.clients[dst]
		s.mu.Unlock()
		if cl != nil {
			cl.sendIP(buf[:n], s.shaper.Target(buf[:n], defaultShapeMTU))
		}
	}
}

// handleConn runs one client's whole lifetime: the TLS/HTTP/SSTP handshake, the
// PPP negotiation and crypto binding, and the data path until the connection ends.
func (s *Server) handleConn(conn *tls.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := conn.Handshake(); err != nil {
		s.logger.Printf("sstp: TLS handshake from %s: %v", conn.RemoteAddr(), err)
		return
	}
	if err := serverHTTPHandshake(conn); err != nil {
		s.logger.Printf("sstp: HTTP handshake from %s: %v", conn.RemoteAddr(), err)
		return
	}
	if err := readCallConnectRequest(conn); err != nil {
		s.logger.Printf("sstp: CallConnectRequest from %s: %v", conn.RemoteAddr(), err)
		return
	}

	nonce := make([]byte, wire.NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return
	}
	if err := sendCallConnectAck(conn, nonce); err != nil {
		return
	}

	ip, err := s.pool.Allocate()
	if err != nil {
		s.logger.Printf("sstp: pool exhausted for %s: %v", conn.RemoteAddr(), err)
		return
	}
	defer s.pool.Release(ip)

	cl := &sstpClient{conn: conn, srv: s, assignedIP: ip}
	cl.ppp = ppp.NewServer(ppp.ServerConfig{
		ClientIP: ip,
		ServerIP: s.gateway,
		DNS:      s.dns,
		Auth:     s.authenticate,
	}, cl, cl)
	defer s.unregister(cl)

	cl.ppp.Start()
	_ = conn.SetDeadline(time.Time{})
	cl.readLoop()
}

// authenticate is the credential lookup the PPP server uses.
func (s *Server) authenticate(username string) (string, bool) {
	pw, ok := s.users[username]
	return pw, ok
}

func (s *Server) register(cl *sstpClient) {
	key := binary.BigEndian.Uint32(cl.assignedIP.To4())
	s.mu.Lock()
	s.clients[key] = cl
	s.mu.Unlock()
}

func (s *Server) unregister(cl *sstpClient) {
	key := binary.BigEndian.Uint32(cl.assignedIP.To4())
	s.mu.Lock()
	if s.clients[key] == cl {
		delete(s.clients, key)
	}
	s.mu.Unlock()
}

// Close stops the server: the listener, the TUN, and every client connection.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		if s.listener != nil {
			s.listener.Close()
		}
		s.mu.Lock()
		for _, cl := range s.clients {
			cl.conn.Close()
		}
		s.mu.Unlock()
		if s.tun != nil {
			s.tun.Close()
		}
	})
	return nil
}

// Abandon implements client.AbandonableServer. It closes the TUN directly, so
// an abandoned listener's packet pump unparks and its descriptor is released
// even though Close never returned. See client.AbandonableServer for why this
// is not simply Close.
//
// The TUN is set in NewServer and never reassigned, so this reads it without
// the lock Close takes -- deliberately, because a wedged Close may be holding
// that lock, and waiting on it here would reproduce the very stall this is the
// escape from.
func (s *Server) Abandon() { s.tun.Close() }

// Server implements client.AbandonableServer, so the supervisor can take its
// descriptors back when Close overruns. Asserted here because the interface is
// found by type assertion at the one call site: without this, a renamed or
// re-signatured Abandon compiles fine and the assertion silently starts failing,
// which reads as the leak coming back.
var _ client.AbandonableServer = (*Server)(nil)

// sstpClient is one accepted client: its TLS connection, PPP server session, and
// assignment. It implements ppp.Transport (framing PPP into SSTP data packets)
// and ppp.ServerHandler (the auth/network lifecycle).
type sstpClient struct {
	conn *tls.Conn
	srv  *Server
	ppp  *ppp.ServerSession

	assignedIP net.IP

	writeMu sync.Mutex

	// Set on authentication, read when the crypto binding arrives.
	password   string
	ntResponse [mschap.NTResponseLen]byte
	authed     bool
}

// SendPPP frames a PPP payload in an SSTP data packet and writes it to the client.
func (c *sstpClient) SendPPP(frame []byte) error {
	pkt, err := wire.EncodeData(frame)
	if err != nil {
		return err
	}
	return c.write(pkt)
}

// sendIP frames one inner packet as PPP inside an SSTP data packet. A non-zero
// padTo pads the PPP Information field out to that size, so the TLS record this
// becomes is the same size whatever the packet was (dataplane/shape.go).
func (c *sstpClient) sendIP(ipPacket []byte, padTo int) {
	frame := ppp.EncapsulateIPPadded(ipPacket, padTo)
	pkt, err := wire.EncodeData(frame)
	if err != nil {
		return
	}
	_ = c.write(pkt)
}

func (c *sstpClient) write(pkt []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	_, err := c.conn.Write(pkt)
	return err
}

// Authenticated records the credentials the crypto binding needs.
func (c *sstpClient) Authenticated(_, password string, ntResponse [mschap.NTResponseLen]byte) {
	c.password = password
	c.ntResponse = ntResponse
	c.authed = true
}

// NetworkUp registers the client so the TUN loop routes its address to it.
func (c *sstpClient) NetworkUp() {
	c.srv.register(c)
	c.srv.logger.Printf("sstp: client %s up, assigned %s", c.conn.RemoteAddr(), c.assignedIP)
}

// Closed ends the connection, unblocking the read loop.
func (c *sstpClient) Closed(err error) {
	if err != nil {
		c.srv.logger.Printf("sstp: client %s: %v", c.conn.RemoteAddr(), err)
	}
	c.conn.Close()
}

// readLoop reads SSTP packets until the connection ends, dispatching control
// packets (the crypto binding, echoes, disconnect) and handing data packets to
// PPP or, once the link is up, to the TUN.
func (c *sstpClient) readLoop() {
	for {
		control, body, err := wire.ReadPacket(c.conn)
		if err != nil {
			return
		}
		if control {
			msg, perr := wire.ParseControl(body)
			if perr != nil {
				continue
			}
			switch msg.Type {
			case wire.MsgCallConnected:
				if err := c.verifyBinding(body); err != nil {
					c.srv.logger.Printf("sstp: crypto binding from %s: %v", c.conn.RemoteAddr(), err)
					c.conn.Close()
					return
				}
				c.srv.logger.Printf("sstp: crypto binding verified for %s", c.conn.RemoteAddr())
			case wire.MsgCallDisconnect:
				return
			case wire.MsgEchoRequest:
				resp, _ := wire.EncodeControl(wire.MsgEchoResponse, nil)
				_ = c.write(resp)
			}
			continue
		}

		if ipPacket, ok := ppp.IsIP(body); ok {
			if _, err := c.srv.tun.Write(ipPacket); err != nil {
				c.srv.logger.Printf("sstp: TUN write: %v", err)
			}
			continue
		}
		c.ppp.Receive(body)
	}
}

// verifyBinding checks the client's CALL_CONNECTED crypto binding: the compound
// MAC over the message under the CMK derived from the client's HLAK, and the hash
// of the server's own certificate. The HLAK is the client's (send||receive) — the
// exact value the client signed with.
func (c *sstpClient) verifyBinding(body []byte) error {
	if !c.authed {
		return errors.New("crypto binding before authentication")
	}
	hlak := mschap.ClientHLAK(c.password, c.ntResponse)
	return VerifyCryptoBinding(body, hlak, c.srv.serverCertDER)
}

// serverHTTPHandshake reads the client's SSTP_DUPLEX_POST request and answers 200,
// after which the connection carries SSTP packets.
func serverHTTPHandshake(conn io.ReadWriter) error {
	line, err := readHTTPHeader(conn)
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	if !strings.HasPrefix(line, "SSTP_DUPLEX_POST ") {
		return fmt.Errorf("unexpected request: %q", line)
	}
	resp := "HTTP/1.1 200 OK\r\n" +
		"Content-Length: 18446744073709551615\r\n" +
		"Server: veepin\r\n" +
		"\r\n"
	_, err = io.WriteString(conn, resp)
	return err
}

// readCallConnectRequest reads and validates the client's CALL_CONNECT_REQUEST.
func readCallConnectRequest(r io.Reader) error {
	control, body, err := wire.ReadPacket(r)
	if err != nil {
		return err
	}
	if !control {
		return errors.New("expected a control packet")
	}
	msg, err := wire.ParseControl(body)
	if err != nil {
		return err
	}
	if msg.Type != wire.MsgCallConnectRequest {
		return fmt.Errorf("unexpected message %#x", msg.Type)
	}
	if attr, ok := msg.Attribute(wire.AttrEncapsulatedProtocolID); ok {
		if len(attr.Value) < 2 || attr.Value[1] != wire.ProtocolPPP {
			return errors.New("client requested a non-PPP encapsulation")
		}
	}
	return nil
}

// sendCallConnectAck sends CALL_CONNECT_ACK carrying the crypto-binding request:
// the server's chosen nonce and the hash it offers (SHA-256). Layout of the value
// (MS-SSTP 2.2.3) is Reserved(3) | HashBitmap(1) | Nonce(32).
func sendCallConnectAck(w io.Writer, nonce []byte) error {
	val := make([]byte, 4+wire.NonceLen)
	val[3] = wire.CertHashSHA256
	copy(val[4:], nonce)
	pkt, err := wire.EncodeControl(wire.MsgCallConnectAck,
		[]wire.Attribute{{ID: wire.AttrCryptoBindingReq, Value: val}})
	if err != nil {
		return err
	}
	_, err = w.Write(pkt)
	return err
}

// ipv4Dst returns the 32-bit destination address of an IPv4 packet.
func ipv4Dst(pkt []byte) (uint32, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(pkt[16:20]), true
}

// defaultShapeMTU is the inner size downstream shaping pads towards. It matches
// the MTU this package reports to a client (client.DefaultTunnelMTU), so a
// padded packet is exactly the size a genuine full one would have been.
const defaultShapeMTU = client.DefaultTunnelMTU

// Server option keys for client.NewServer("sstp", opts).
const (
	OptServerCert     = "cert"
	OptServerKey      = "key"
	OptServerListenIP = "listen"
	OptServerPort     = "port"
	OptServerPool     = "pool"
	OptServerDNS      = "dns"
	OptServerUser     = "user"
	OptServerPassword = "password"
	OptServerUsers    = "users-file"
	OptServerTUN      = "tun"
	OptServerShape    = "shape" // per-flow downstream shaping budget in bytes (0 = off)
)

func init() {
	client.RegisterServer("sstp", parseServerOptions)
	client.RegisterServerOpts("sstp", []client.OptSpec{
		{Key: OptServerCert, Kind: client.OptFilePath, Required: true, Generate: "tls", Help: "path to the server TLS certificate PEM"},
		{Key: OptServerKey, Kind: client.OptFilePath, Required: true, Secret: true, Generate: "tls", Help: "path to the server TLS private key PEM"},
		{Key: OptServerListenIP, Kind: client.OptStr, Default: "0.0.0.0", Help: "local IP to bind the TCP socket on (default 0.0.0.0)"},
		{Key: OptServerPort, Kind: client.OptInt, Default: "443", Help: "TCP port to listen on (default 443)"},
		{Key: OptServerPool, Kind: client.OptCIDR, Default: "10.9.0.0/24", Help: "internal address pool handed to clients (default 10.9.0.0/24)"},
		{Key: OptServerDNS, Kind: client.OptCommaList, Help: "comma-separated DNS servers assigned to clients"},
		{Key: OptServerUser, Kind: client.OptStr, Help: "MS-CHAPv2 username to accept; the one-user shorthand for users-file, and one of the two is required"},
		{Key: OptServerPassword, Flag: "pass", Kind: client.OptStr, Secret: true, Help: "the password for user"},
		{Key: OptServerUsers, Kind: client.OptFilePath, Secret: true, Help: "path to a file of username:secret lines, for more than one user; MS-CHAPv2 derives its response from the password, so the secret must be the password itself"},
		client.TUNOpt(OptServerTUN),
		client.ShapeOpt(OptServerShape, "downstream"),
	})
}

// parseServerOptions builds an SSTP responder from string options. A single user
// is configured via the user/password options.
func parseServerOptions(opts map[string]string) (client.Server, error) {
	cfg := ServerConfig{
		ListenIP: opts[OptServerListenIP],
		Pool:     opts[OptServerPool],
		TUNName:  opts[OptServerTUN],
		Users:    map[string]string{},

		PostQuantumOnly: pqpolicy.Requested(opts),
		Logger:          slog.New(vlog.NewTextHandler(os.Stdout, slog.LevelInfo)),
	}
	var err error
	if cfg.Cert, err = os.ReadFile(opts[OptServerCert]); err != nil {
		return nil, fmt.Errorf("sstp: cert: %w", err)
	}
	if cfg.Key, err = os.ReadFile(opts[OptServerKey]); err != nil {
		return nil, fmt.Errorf("sstp: key: %w", err)
	}
	if cfg.Users, err = userdb.Resolve(userdb.NeedsPlaintext, opts[OptServerUsers], opts[OptServerUser], opts[OptServerPassword]); err != nil {
		return nil, fmt.Errorf("sstp: %w", err)
	}
	if v := opts[OptServerPort]; v != "" {
		p, perr := strconv.Atoi(v)
		if perr != nil {
			return nil, fmt.Errorf("sstp: invalid port %q", v)
		}
		cfg.ListenPort = p
	}
	for d := range strings.SplitSeq(opts[OptServerDNS], ",") {
		if d = strings.TrimSpace(d); d != "" {
			if ip := net.ParseIP(d); ip != nil {
				cfg.DNS = append(cfg.DNS, ip)
			}
		}
	}
	if v := opts[OptServerShape]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("sstp: invalid %s %q", OptServerShape, v)
		}
		cfg.Shape = n
	}
	return NewServer(cfg)
}
