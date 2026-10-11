package fortinet

// The server role: a Fortinet SSL VPN gateway.
//
// It runs an HTTPS server whose handler is internal/fortinet's — login, config,
// and the hijacked PPP tunnel — alongside a read loop over the shared TUN. The
// facade mirrors every other server here: NewServer validates configuration and
// opens the TUN but binds no socket, so the caller configures host networking
// before ListenAndServe.

import (
	"crypto/ecdsa"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	ifortinet "github.com/xen0bit/veepin/internal/fortinet"
	"github.com/xen0bit/veepin/internal/otp"
	"github.com/xen0bit/veepin/internal/pqpolicy"
	"github.com/xen0bit/veepin/internal/userdb"
	"github.com/xen0bit/veepin/internal/vlog"
)

func init() {
	client.RegisterServer("fortinet", parseServerOptions)
	client.RegisterServerOpts("fortinet", []client.OptSpec{
		{Key: OptServerCert, Kind: client.OptFilePath, Required: true, Generate: "tls", Help: "path to the server TLS certificate PEM"},
		{Key: OptServerKey, Kind: client.OptFilePath, Required: true, Secret: true, Generate: "tls", Help: "path to the server TLS private key PEM"},
		{Key: OptServerListen, Kind: client.OptStr, Default: "0.0.0.0", Help: "local IP to bind the HTTPS socket on (default 0.0.0.0)"},
		{Key: OptServerPort, Kind: client.OptInt, Default: "443", Help: "HTTPS port to listen on (default 443)"},
		{Key: OptServerPool, Kind: client.OptCIDR, Default: "10.40.0.0/24", Help: "internal address pool handed to clients (default 10.40.0.0/24)"},
		{Key: OptServerDNS, Kind: client.OptCommaList, Help: "comma-separated DNS servers offered to clients"},
		{Key: OptServerUser, Kind: client.OptStr, Help: "username to accept; the one-user shorthand for users-file, and one of the two is required"},
		{Key: OptServerPass, Kind: client.OptStr, Secret: true, Help: "the password for user"},
		{Key: OptServerUsers, Kind: client.OptFilePath, Secret: true, Help: "path to a file of username:secret lines, for more than one user; the secret may be a bcrypt verifier"},
		{Key: OptServerNoDTLS, Kind: client.OptBool, Help: "serve the TLS tunnel only, leaving the UDP port unbound"},
		{Key: OptServerTOTP, Kind: client.OptStr, Secret: true, Help: "base32 TOTP secret; set it to require a second factor from the user"},
		client.TUNOpt(OptServerTUN),
		client.ShapeOpt(OptServerShape, "downstream"),
	})
}

const defaultPool = "10.40.0.0/24"

// Server option keys accepted by client.NewServer("fortinet", opts).
const (
	OptServerListen = "listen"     // local IP to bind (default 0.0.0.0)
	OptServerPort   = "port"       // HTTPS port (default 443)
	OptServerPool   = "pool"       // client address pool CIDR
	OptServerCert   = "cert"       // TLS certificate PEM (required)
	OptServerKey    = "key"        // TLS private key PEM (required)
	OptServerUser   = "user"       // username to accept (required)
	OptServerPass   = "pass"       // that user's password (required)
	OptServerUsers  = "users-file" // path to a file of username:secret lines (more than one user)
	OptServerDNS    = "dns"        // comma-separated DNS servers offered to clients
	OptServerNoDTLS = "no-dtls"    // "true" to serve the TLS tunnel only
	OptServerTOTP   = "totp"       // base32 TOTP secret; set it to require a second factor
	OptServerTUN    = "tun"        // TUN interface name
	OptServerShape  = "shape"      // per-flow downstream shaping budget in bytes (0 = off)
)

// ServerConfig configures a Fortinet SSL VPN server.
type ServerConfig struct {
	ListenIP string
	Port     int
	Pool     string
	Cert     []byte
	Key      []byte
	Users    map[string]string
	DNS      []net.IP
	// NoDTLS serves the TLS tunnel only, leaving the UDP port unbound.
	NoDTLS bool
	// TOTPSecrets maps a username to its base32 TOTP secret. A user listed here
	// must pass a second factor after its password.
	TOTPSecrets map[string]string
	TUNName     string

	// Shape enables downstream traffic shaping: how much padded output each
	// inner flow is given before shaping stops for that flow, so it bounds what
	// shaping costs. A flow gets Shape/MTU padded packets whatever sizes it
	// carries. Zero, the default, disables it.
	//
	// It hides the size pattern of an inner TLS handshake, which otherwise
	// shows through as the size of the TLS record carrying it (see
	// dataplane/shape.go). Clients need no support for it — the padding is
	// RFC 1661 §5.1 PPP padding, which every conforming peer trims by the inner
	// IP header — so a stock FortiClient or openconnect benefits unmodified.
	// dataplane.DefaultShapeBytes is a reasonable value.
	Shape int

	Logger *slog.Logger

	// PostQuantumOnly requires a post-quantum key exchange and ML-DSA
	// authentication, refusing anything less rather than negotiating down. It is
	// what the pq-fortinet registry name sets; see internal/pqpolicy for the contract
	// and doc/pq-variants-plan.md for why it is a name rather than a flag.
	PostQuantumOnly bool
}

// Server is a Fortinet SSL VPN server.
type Server struct {
	cfg     ServerConfig
	tlsCfg  *tls.Config
	pool    *dataplane.AddrPool
	gateway net.IP
	tun     *dataplane.TUN
	engine  *ifortinet.Server
	dtlsOK  bool // the UDP data channel is configured and will be bound

	mu      sync.Mutex
	httpSrv *http.Server
	udpConn *net.UDPConn
	started bool
	closed  bool
}

// NewServer validates the configuration, loads the keypair, allocates the pool
// and opens the TUN. It binds no socket and changes no host state.
func NewServer(cfg ServerConfig) (*Server, error) {
	if len(cfg.Cert) == 0 || len(cfg.Key) == 0 {
		return nil, errors.New("fortinet: a TLS certificate and key are required")
	}
	if len(cfg.Users) == 0 {
		return nil, errors.New("fortinet: at least one user is required")
	}
	cert, err := tls.X509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("fortinet: server keypair: %w", err)
	}

	if cfg.PostQuantumOnly {
		// Here, next to the parse, rather than beside the HardenTLS call below:
		// this is the last point before dataplane.OpenTUN, and the promise the
		// check exists to keep is that an operator who pointed a pq- name at
		// their existing RSA certificate learns it before the listener acquires
		// anything. It used to sit below, under a comment saying it was here --
		// which also meant the refusal returned without closing the TUN it had
		// by then opened, leaking a file descriptor per attempt.
		if err := pqpolicy.CheckCredential(cert); err != nil {
			return nil, err
		}
	}

	poolCIDR := cfg.Pool
	if poolCIDR == "" {
		poolCIDR = defaultPool
	}
	pool, gateway, err := dataplane.NewAddrPool(poolCIDR)
	if err != nil {
		return nil, fmt.Errorf("fortinet: address pool %q: %w", poolCIDR, err)
	}
	// Validated before the TUN is opened, not after: it needs nothing from the
	// TUN, and returning from between the open and the first close leaked the
	// interface on a typo'd secret.
	for user, secret := range cfg.TOTPSecrets {
		if _, err := otp.DecodeSecret(secret); err != nil {
			return nil, fmt.Errorf("fortinet: TOTP secret for %q: %w", user, err)
		}
	}

	tun, err := dataplane.OpenTUN(cfg.TUNName)
	if err != nil {
		return nil, fmt.Errorf("fortinet: opening TUN: %w", err)
	}

	engineCfg := ifortinet.ServerConfig{
		Users:       cfg.Users,
		Pool:        pool,
		ServerIP:    gateway,
		DNS:         cfg.DNS,
		Logger:      vlog.From(cfg.Logger),
		TOTPSecrets: cfg.TOTPSecrets,
		Shape:       cfg.Shape,
		MTU:         client.DefaultTunnelMTU,
	}
	// The DTLS channel is ECDHE-ECDSA, so an RSA gateway keypair cannot serve it.
	// That is a reason to run TLS-only, not to refuse to start: the TLS tunnel is
	// unaffected and is what every client can already speak.
	if !cfg.NoDTLS {
		if _, ok := cert.PrivateKey.(*ecdsa.PrivateKey); ok {
			engineCfg.Certificate = &cert
		} else if cfg.Logger != nil {
			vlog.From(cfg.Logger).Printf("fortinet: server key is not ECDSA; the DTLS data channel is disabled")
		}
	}
	engine, err := ifortinet.NewServer(engineCfg, tun)
	if err != nil {
		_ = tun.Close()
		return nil, err
	}

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if cfg.PostQuantumOnly {
		// The credential was judged above, before the TUN. What is left here is
		// the config, which cannot be hardened before it exists.
		pqpolicy.HardenTLS(tlsCfg)
	}

	return &Server{
		cfg:     cfg,
		dtlsOK:  engineCfg.Certificate != nil,
		tlsCfg:  tlsCfg,
		pool:    pool,
		gateway: gateway,
		tun:     tun,
		engine:  engine,
	}, nil
}

// ListenAndServe binds the HTTPS socket and serves until Close. It blocks.
func (s *Server) ListenAndServe() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	if s.started {
		s.mu.Unlock()
		return errors.New("fortinet: server already started")
	}
	s.started = true

	port := s.cfg.Port
	if port == 0 {
		port = defaultPort
	}
	listenIP := s.cfg.ListenIP
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}
	addr := net.JoinHostPort(listenIP, strconv.Itoa(port))
	ln, err := tls.Listen("tcp", addr, s.tlsCfg)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("fortinet: listen: %w", err)
	}

	// The UDP data channel shares the port number. It is bound and its serve loop
	// started before the HTTPS listener accepts anything, so no client is ever
	// told about a channel that is not yet being read.
	var serveDTLS func()
	if s.dtlsOK {
		udp, uerr := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(listenIP), Port: port})
		if uerr != nil {
			_ = ln.Close()
			s.mu.Unlock()
			return fmt.Errorf("fortinet: listen UDP: %w", uerr)
		}
		serveDTLS, err = s.engine.EnableDTLS(udp)
		if err != nil {
			_ = udp.Close()
			_ = ln.Close()
			s.mu.Unlock()
			return err
		}
		s.udpConn = udp
	}
	s.httpSrv = &http.Server{Handler: s.engine}
	s.mu.Unlock()

	if serveDTLS != nil {
		go serveDTLS()
	}
	go s.engine.RunTUN()

	if err := s.httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("fortinet: serve: %w", err)
	}
	return nil
}

// Close stops the server.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	httpSrv := s.httpSrv
	s.mu.Unlock()

	if httpSrv != nil {
		_ = httpSrv.Close()
	}
	return s.engine.Close()
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

// TUNName is the interface the server is bound to.
func (s *Server) TUNName() string {
	if s.tun == nil {
		return ""
	}
	return s.tun.Name()
}

// Gateway is the server's own address inside the tunnel.
func (s *Server) Gateway() net.IP { return s.gateway }

// Network is the tunnel subnet client addresses come from.
func (s *Server) Network() *net.IPNet { return s.pool.Network() }

// parseServerOptions turns registry options into a constructed Server.
func parseServerOptions(opts map[string]string) (client.Server, error) {
	cfg := ServerConfig{
		ListenIP: opts[OptServerListen],
		Pool:     opts[OptServerPool],
		NoDTLS:   opts[OptServerNoDTLS] == "true",
		TUNName:  opts[OptServerTUN],
		Logger:   vlog.SlogText(logDest()),

		PostQuantumOnly: pqpolicy.Requested(opts),
	}
	user, pass := opts[OptServerUser], opts[OptServerPass]
	if user != "" && pass == "" {
		return nil, errors.New("fortinet: a named user needs a pass")
	}
	users, uerr := userdb.Resolve(userdb.Verifiable, opts[OptServerUsers], user, pass)
	if uerr != nil {
		return nil, fmt.Errorf("fortinet: %w", uerr)
	}
	if len(users) == 0 {
		return nil, errors.New("fortinet: user and pass, or users-file, are required")
	}
	if secret := opts[OptServerTOTP]; secret != "" {
		// The TOTP secret is still per-invocation and therefore still names one
		// user: a second factor is a per-person enrolment, and expressing it in
		// the credentials file would mean a file format that carries two
		// unrelated kinds of secret. -totp without -user has nobody to enrol.
		if user == "" {
			return nil, errors.New("fortinet: totp names the second factor for -user, which is unset")
		}
		cfg.TOTPSecrets = map[string]string{user: secret}
	}
	cfg.Users = users

	if v := opts[OptServerPort]; v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p <= 0 || p > 65535 {
			return nil, fmt.Errorf("fortinet: invalid port %q", v)
		}
		cfg.Port = p
	}
	if v := opts[OptServerShape]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("fortinet: invalid shape %q", v)
		}
		cfg.Shape = n
	}
	for _, d := range strings.Split(opts[OptServerDNS], ",") {
		if d = strings.TrimSpace(d); d != "" {
			if ip := net.ParseIP(d); ip != nil {
				cfg.DNS = append(cfg.DNS, ip)
			}
		}
	}

	var err error
	if cfg.Cert, err = readFile(opts[OptServerCert]); err != nil {
		return nil, fmt.Errorf("fortinet: certificate: %w", err)
	}
	if cfg.Key, err = readFile(opts[OptServerKey]); err != nil {
		return nil, fmt.Errorf("fortinet: key: %w", err)
	}
	return NewServer(cfg)
}
