package anyconnect

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	engine "github.com/xen0bit/veepin/internal/anyconnect"
	"github.com/xen0bit/veepin/internal/pqpolicy"
	"github.com/xen0bit/veepin/internal/userdb"
	"github.com/xen0bit/veepin/internal/vlog"
)

func init() {
	client.RegisterServer("anyconnect", parseServerOptions)
	client.RegisterServerOpts("anyconnect", []client.OptSpec{
		{Key: OptServerCert, Kind: client.OptFilePath, Required: true, Generate: "tls", Help: "path to the server TLS certificate PEM"},
		{Key: OptServerKey, Kind: client.OptFilePath, Required: true, Secret: true, Generate: "tls", Help: "path to the server TLS private key PEM"},
		{Key: OptServerListen, Kind: client.OptStr, Default: "0.0.0.0", Help: "local IP to bind the TCP socket on (default 0.0.0.0)"},
		{Key: OptServerPort, Kind: client.OptInt, Default: "443", Help: "TCP port to listen on (default 443)"},
		{Key: OptServerPool, Kind: client.OptCIDR, Default: "10.11.0.0/24", Help: "internal address pool handed to clients (default 10.11.0.0/24)"},
		{Key: OptServerDNS, Kind: client.OptCommaList, Help: "comma-separated DNS servers assigned to clients"},
		{Key: OptServerUser, Kind: client.OptStr, Help: "username to accept; the one-user shorthand for users-file, and one of the two is required"},
		{Key: OptServerPassword, Flag: "pass", Kind: client.OptStr, Secret: true, Help: "the password for user"},
		{Key: OptServerUsers, Kind: client.OptFilePath, Secret: true, Help: "path to a file of username:secret lines, for more than one user; the secret may be a bcrypt verifier"},
		client.TUNOpt(OptServerTUN),
		{Key: OptServerNoDTLS, Kind: client.OptBool, Help: "serve the TLS tunnel only, leaving the UDP port unbound"},
		client.ShapeOpt(OptServerShape, "downstream"),
	})
}

// Server option keys for client.NewServer("anyconnect", opts).
const (
	OptServerCert     = "cert"
	OptServerKey      = "key"
	OptServerListen   = "listen"
	OptServerPort     = "port"
	OptServerUser     = "user"
	OptServerPassword = "password"
	OptServerUsers    = "users-file"
	OptServerPool     = "pool"
	OptServerDNS      = "dns"
	OptServerTUN      = "tun"
	OptServerNoDTLS   = "no-dtls"
	OptServerShape    = "shape" // per-flow downstream shaping budget in bytes (0 = off)
)

const defaultPool = "10.11.0.0/24"

// ServerConfig configures an AnyConnect responder and its userspace data path.
type ServerConfig struct {
	// Cert and Key are the server's TLS certificate and private key, PEM
	// (required). Clients verify this unless they opt out.
	Cert []byte
	Key  []byte
	// ListenIP is the local address to bind on; empty binds all interfaces.
	ListenIP string
	// ListenPort is the TCP port to accept clients on (default 443).
	ListenPort int
	// Users maps a username to its password (at least one required).
	Users map[string]string
	// Pool is the internal address pool handed to clients, CIDR (default
	// 10.11.0.0/24). Its first host is the server's tunnel address.
	Pool string
	// DNS servers assigned to clients.
	DNS []net.IP
	// TUNName is the desired TUN interface name; empty lets the kernel pick.
	TUNName string
	// NoDTLS serves the TLS data channel only, without binding a UDP socket.
	NoDTLS bool

	// Shape enables downstream traffic shaping: how much padded output each
	// inner flow is given before shaping stops for that flow, so it bounds what
	// shaping costs. A flow gets Shape/MTU padded packets whatever sizes it
	// carries. Zero, the default, disables it.
	//
	// It hides the size pattern of an inner TLS handshake, which otherwise shows
	// through as the size of the CSTP packet carrying it (see dataplane/shape.go).
	// Clients need no support for it: CSTP length-delimits its payload, so the
	// filler after the inner packet is trimmed by the IP header's Total Length,
	// as every IP stack must. dataplane.DefaultShapeBytes is a reasonable value.
	Shape int

	Logger *slog.Logger

	// PostQuantumOnly requires a post-quantum key exchange and ML-DSA
	// authentication, refusing anything less rather than negotiating down. It is
	// what the pq-anyconnect registry name sets; see internal/pqpolicy for the contract
	// and doc/pq-variants-plan.md for why it is a name rather than a flag.
	PostQuantumOnly bool
}

func (c *ServerConfig) validate() error {
	switch {
	case len(c.Cert) == 0 || len(c.Key) == 0:
		return fmt.Errorf("anyconnect: server certificate and key are required")
	case len(c.Users) == 0:
		return fmt.Errorf("anyconnect: at least one user is required")
	}
	return nil
}

// Server is a running AnyConnect responder. It owns the TUN and the TLS
// listener but, like the other protocols, configures no host networking —
// Gateway and Network report what the caller needs to do that.
type Server struct {
	eng      *engine.Server
	tun      *dataplane.TUN
	pool     *dataplane.AddrPool
	gateway  net.IP
	listener net.Listener
	logger   *vlog.Logger
	gate     *dataplane.Gate

	closeOnce sync.Once
}

// NewServer opens the TUN, creates the address pool, and binds the listener. It
// does not accept clients until ListenAndServe.
func NewServer(cfg ServerConfig) (*Server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	logger := vlog.From(cfg.Logger)
	cert, err := tls.X509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("anyconnect: server keypair: %w", err)
	}
	poolCIDR := cfg.Pool
	if poolCIDR == "" {
		poolCIDR = defaultPool
	}
	pool, gateway, err := dataplane.NewAddrPool(poolCIDR)
	if err != nil {
		return nil, fmt.Errorf("anyconnect: address pool: %w", err)
	}
	port := cfg.ListenPort
	if port == 0 {
		port = defaultPort
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if cfg.PostQuantumOnly {
		// Checked before the TUN is opened and before anything binds: an
		// operator who pointed a pq- name at their existing RSA certificate
		// learns it here, rather than from a listener that comes up and then
		// refuses every client.
		if err := pqpolicy.CheckCredential(cert); err != nil {
			return nil, err
		}
		pqpolicy.HardenTLS(tlsCfg)
	}
	ln, err := tls.Listen("tcp", net.JoinHostPort(cfg.ListenIP, strconv.Itoa(port)), tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("anyconnect: listen: %w", err)
	}
	// The DTLS data channel shares the TLS port, on UDP. Failing to bind it is
	// not fatal: the tunnel works over TLS, which is what the protocol falls back
	// to whenever UDP is unavailable.
	var udpConn *net.UDPConn
	if !cfg.NoDTLS {
		udpConn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(cfg.ListenIP), Port: port})
		if err != nil {
			logger.Printf("anyconnect: no DTLS data channel (bind udp/%d: %v)", port, err)
			udpConn = nil
		}
	}
	tun, err := dataplane.OpenTUN(cfg.TUNName)
	if err != nil {
		ln.Close()
		if udpConn != nil {
			udpConn.Close()
		}
		return nil, fmt.Errorf("anyconnect: open TUN: %w", err)
	}

	eng := engine.NewServer(tun, engine.ServerConfig{
		Users:    cfg.Users,
		Pool:     pool,
		Gateway:  gateway,
		DNS:      cfg.DNS,
		DTLSConn: udpConn,
		Shape:    cfg.Shape,
		Logger:   logger,
	})
	return &Server{
		eng: eng, tun: tun, pool: pool, gateway: gateway,
		listener: ln, logger: logger,
		gate: dataplane.NewGate(dataplane.AdmissionConfig{}),
	}, nil
}

// ListenAndServe accepts clients until Close. It blocks.
func (s *Server) ListenAndServe() error {
	s.eng.Start()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			// A closed listener is the ordinary shutdown path, not a failure.
			return nil
		}
		// The XML credential exchange and CONNECT that follow are performed for
		// an unauthenticated peer, so the bound belongs at accept.
		if r := s.gate.Admit(conn.RemoteAddr()); r != dataplane.Admitted {
			s.logger.Warnf("anyconnect: refusing connection from %s: %v", conn.RemoteAddr(), r)
			_ = conn.Close()
			continue
		}
		go func(c net.Conn) {
			defer s.gate.Done()
			s.eng.ServeConn(c)
		}(conn)
	}
}

// Close stops the server and releases the TUN and listener.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.listener.Close()
		_ = s.eng.Close()
		s.tun.Close()
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

// TUNName is the interface the data path is bound to.
func (s *Server) TUNName() string { return s.tun.Name() }

// Gateway is the server's own tunnel-side address (the pool's first host).
func (s *Server) Gateway() net.IP { return s.gateway }

// Network is the tunnel subnet, for routing and NAT rules.
func (s *Server) Network() *net.IPNet { return s.pool.Network() }

func parseServerOptions(opts map[string]string) (client.Server, error) {
	cfg := ServerConfig{
		ListenIP: opts[OptServerListen],
		Pool:     opts[OptServerPool],
		DNS:      parseIPList(opts[OptServerDNS]),
		TUNName:  opts[OptServerTUN],
		NoDTLS:   opts[OptServerNoDTLS] == "true",
		Logger:   slog.New(vlog.NewTextHandler(os.Stdout, slog.LevelInfo)),

		PostQuantumOnly: pqpolicy.Requested(opts),
	}
	if path := opts[OptServerCert]; path != "" {
		pem, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("anyconnect: read cert: %w", err)
		}
		cfg.Cert = pem
	}
	if path := opts[OptServerKey]; path != "" {
		pem, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("anyconnect: read key: %w", err)
		}
		cfg.Key = pem
	}
	if v := opts[OptServerShape]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("anyconnect: invalid shape %q", v)
		}
		cfg.Shape = n
	}
	if v := opts[OptServerPort]; v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("anyconnect: invalid port %q", v)
		}
		cfg.ListenPort = p
	}
	users, uerr := userdb.Resolve(userdb.Verifiable, opts[OptServerUsers], opts[OptServerUser], opts[OptServerPassword])
	if uerr != nil {
		return nil, fmt.Errorf("anyconnect: %w", uerr)
	}
	cfg.Users = users
	return NewServer(cfg)
}
