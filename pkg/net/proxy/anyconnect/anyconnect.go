// Package anyconnect is the public entry point for the Cisco AnyConnect SSL VPN
// protocol — the wire protocol OpenConnect and ocserv speak, specified as
// draft-mavrogiannopoulos-openconnect.
//
// The tunnel runs over HTTPS: an XML credential exchange, then a CONNECT whose
// response headers carry the client's address, netmask, DNS and MTU, after which
// the same TLS connection carries IP packets under an 8-octet framing. There is
// no PPP layer — unlike SSTP, addressing is negotiated in HTTP headers.
//
// Like every protocol here, Dial installs no addresses, routes or DNS: it
// returns the negotiated Result for the caller to apply. Importing this package
// registers "anyconnect" with the client registry:
//
//	import _ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/anyconnect"
//	sess, res, err := client.Dial(ctx, "anyconnect", opts)
package anyconnect

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	engine "github.com/Asutorufa/yuhaiin/pkg/net/proxy/anyconnect/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/dataplane"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/session"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/vlog"
)

func init() { client.Register("anyconnect", parseOptions) }

// Option names for client.Dial.
const (
	OptServer   = "server"
	OptPort     = "port"
	OptUser     = "user"
	OptPassword = "password"
	OptInsecure = "insecure" // skip TLS certificate verification
	OptNoDTLS   = "no-dtls"  // stay on the TLS data channel
	OptTUNName  = "tun"
)

// defaultPort is the HTTPS port AnyConnect servers listen on.
const defaultPort = 443

// keepaliveInterval holds an idle connection open through NAT and stateful
// firewalls. The server advertises its own preference, but a client-side floor
// keeps the tunnel alive against middleboxes with shorter timeouts.
const keepaliveInterval = 20 * time.Second

// Config holds the parameters for one AnyConnect tunnel.
type Config struct {
	DialContext func(context.Context, string, string) (net.Conn, error)
	Server      string // server host or IP (required)
	Port        int    // HTTPS port (default 443)
	Username    string // (required)
	Password    string // (required)
	// Insecure skips TLS certificate verification, for self-signed test servers.
	Insecure bool
	// NoDTLS keeps the tunnel on TLS even when the server offers a UDP channel.
	NoDTLS  bool
	TUNName string
	Logger  *slog.Logger
}

func (c *Config) validate() error {
	switch {
	case c.Server == "":
		return fmt.Errorf("anyconnect: server is required")
	case c.Username == "":
		return fmt.Errorf("anyconnect: user is required")
	case c.Password == "":
		return fmt.Errorf("anyconnect: password is required")
	}
	return nil
}

func parseOptions(opts map[string]string) (client.Dialer, error) {
	cfg := &Config{
		// Whether the data channel ended up on UDP or fell back to TCP is
		// operationally significant — it is the difference between a tunnel that
		// performs and one that does not — so the engine's log is surfaced rather
		// than discarded. The other client protocols predate this and stay quiet.
		Logger:   slog.New(vlog.NewTextHandler(os.Stdout, slog.LevelInfo)),
		Server:   opts[OptServer],
		Username: opts[OptUser],
		Password: opts[OptPassword],
		Insecure: opts[OptInsecure] == "true",
		NoDTLS:   opts[OptNoDTLS] == "true",
		TUNName:  opts[OptTUNName],
	}
	if v := opts[OptPort]; v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("anyconnect: invalid port %q", v)
		}
		cfg.Port = p
	}
	return dialer{cfg}, cfg.validate()
}

type dialer struct{ cfg *Config }

func (d dialer) Dial(ctx context.Context) (client.Session, client.Result, error) {
	return Dial(ctx, *d.cfg)
}

// Dial authenticates, opens the tunnel, brings up a TUN, and returns the
// addressing the server assigned for the caller to apply.
func Dial(ctx context.Context, cfg Config) (client.Session, client.Result, error) {
	if err := cfg.validate(); err != nil {
		return nil, client.Result{}, err
	}
	logger := vlog.From(cfg.Logger)
	port := cfg.Port
	if port == 0 {
		port = defaultPort
	}
	addr := net.JoinHostPort(cfg.Server, strconv.Itoa(port))

	dialer := &net.Dialer{}
	tlsCfg := &tls.Config{
		ServerName:         cfg.Server,
		InsecureSkipVerify: cfg.Insecure, //nolint:gosec // opt-in; documented
		MinVersion:         tls.VersionTLS12,
	}

	var conn *tls.Conn
	var err error
	if cfg.DialContext != nil {
		var raw net.Conn
		raw, err = cfg.DialContext(ctx, "tcp", addr)
		if err == nil {
			conn = tls.Client(raw, tlsCfg)
			err = conn.HandshakeContext(ctx)
			if err != nil {
				conn.Close()
			}
		}
	} else {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	}
	if err != nil {
		return nil, client.Result{}, fmt.Errorf("anyconnect: connect %s: %w", addr, err)
	}

	// The Host header must carry the port whenever it is not the default, since
	// servers match their virtual host on it.
	host := cfg.Server
	if port != defaultPort {
		host = addr
	}
	tun, err := dataplane.OpenTUN(cfg.TUNName)
	if err != nil {
		conn.Close()
		return nil, client.Result{}, fmt.Errorf("anyconnect: open TUN: %w", err)
	}

	c := engine.NewClient(conn, tun, engine.ClientConfig{
		Host:     host,
		Hostname: cfg.TUNName,
		Username: cfg.Username,
		Password: cfg.Password,
		NoDTLS:   cfg.NoDTLS,
		Logger:   logger,
	})

	// Handshake is synchronous; the context bounds it by closing the connection,
	// which unblocks the read in progress.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()

	tcfg, err := c.Handshake()
	if err != nil {
		tun.Close()
		conn.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, client.Result{}, fmt.Errorf("anyconnect: %w", ctxErr)
		}
		return nil, client.Result{}, client.WrapAuth(err, engine.ErrAuth)
	}
	logger.Printf("anyconnect: tunnel up on %s, address %s", tun.Name(), tcfg.Address)

	// Bring up the UDP data channel if the server offered one. This is best
	// effort by design: the tunnel already works over TLS, and the protocol
	// treats that as the fallback whenever UDP is unavailable.
	if !cfg.NoDTLS {
		c.StartDTLS()
	}

	sess := &session{engine: c, tun: tun, errc: make(chan error, 1)}
	go func() { sess.errc <- c.Run(keepaliveInterval) }()

	res := client.Result{
		TUNName:    tun.Name(),
		AssignedIP: tcfg.Address,
		Netmask:    tcfg.Netmask,
		// Gateway is the server's outer IP: the router pins a host route to it so
		// the TLS carrier does not recurse into the tunnel.
		Gateway: remoteIP(conn),
		DNS:     tcfg.DNS,
		MTU:     tcfg.MTU,
	}
	return sess, res, nil
}

// remoteIP is the server's outer address, taken from the established connection
// so it reflects what DNS actually resolved to.
func remoteIP(conn net.Conn) net.IP {
	if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return ta.IP
	}
	return nil
}

// session is a running AnyConnect tunnel implementing client.Session.
type session struct {
	engine *engine.Client
	tun    *dataplane.TUN
	errc   chan error
}

// Probe implements client.Prober.
//
// client/liveness.go names AnyConnect's DTLS path as one that can black-hole
// silently, and the reason it needs a probe rather than relying on the TLS
// connection is that the two carriers fail differently: TLS surfaces a dead
// peer through a read error, while a DTLS channel whose NAT binding has expired
// simply stops delivering. Data goes over DTLS whenever it is up, so a healthy
// idle TLS connection beside a dead UDP path is a tunnel that reports itself up
// and carries nothing.
//
// The probe is sent on whichever carrier is currently moving data, which is the
// only way it tests the path that matters.
func (s *session) Probe(ctx context.Context) error { return s.engine.Probe(ctx) }

// LivenessConfig implements client.LivenessTuner. A DPD round trip is one
// datagram each way, so it is cheap enough to run often; the tolerance comes
// from MaxFailures rather than from a long interval, because a single lost UDP
// datagram must not be read as a dead peer.
func (s *session) LivenessConfig() client.LivenessConfig {
	return client.LivenessConfig{
		Interval:    10 * time.Second,
		Timeout:     3 * time.Second,
		MaxFailures: 3,
	}
}

func (s *session) Wait(ctx context.Context) error {
	select {
	case err := <-s.errc:
		return err
	case <-ctx.Done():
		_ = s.Close()
		return ctx.Err()
	}
}

func (s *session) Close() error {
	err := s.engine.Close()
	s.tun.Close()
	return err
}

// parseIPList parses a comma/space-separated list of IPs, dropping anything
// unparseable.
func parseIPList(list string) []net.IP {
	fields := strings.FieldsFunc(list, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	var out []net.IP
	for _, s := range fields {
		if ip := net.ParseIP(s); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}
