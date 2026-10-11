// Package fortinet is the public entry point to the Fortinet FortiOS SSL VPN:
// an HTTPS login and config exchange, then a PPP-over-TLS data tunnel. It is the
// second enterprise SSL VPN in veepin next to AnyConnect, and reuses the most —
// internal/ppp for the link and the ordinary TLS stack for the carrier.
//
// The shape is the one every veepin client follows: Dial authenticates, learns
// the assigned address and routes, and returns a client.Result the caller
// applies — it installs no addresses or routes itself.
package fortinet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strconv"
	"time"

	ifortinet "github.com/Asutorufa/yuhaiin/pkg/net/proxy/fortinet/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/dataplane"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/otp"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/session"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/vlog"
)

func init() { client.Register("fortinet", parseOptions) }

// defaultPort is the FortiOS SSL VPN HTTPS port.
const defaultPort = 443

// defaultMaskBits is the netmask the client assumes for its assigned address.
// FortiOS carries no netmask in the config, and the assigned address sits in the
// same subnet the server's pool draws from, so a /24 puts the gateway on-link —
// the shape every other protocol here hands back. -no-route or a full-tunnel
// default route override it when a caller wants different routing.
const defaultMaskBits = 24

// Option keys accepted by client.Dial(ctx, "fortinet", opts).
const (
	OptServer   = "server"   // proxy host or IP (required)
	OptPort     = "port"     // HTTPS port (default 443)
	OptUser     = "user"     // username (required)
	OptPassword = "password" // password (required)
	OptRealm    = "realm"    // FortiOS realm (optional)
	OptCA       = "ca"       // PEM bundle to verify the server
	OptInsecure = "insecure" // "true" to skip certificate verification
	OptNoDTLS   = "no-dtls"  // "true" to stay on the TLS tunnel even if UDP is offered
	OptToken    = "token"    // a one-time code to answer a 2FA challenge with
	OptTOTP     = "totp"     // base32 TOTP secret, so codes are generated as needed
	OptTUN      = "tun"      // TUN interface name
)

// Config is the parsed client configuration.
type Config struct {
	DialContext func(context.Context, string, string) (net.Conn, error)
	Server      string
	Port        int
	Username    string
	Password    string
	Realm       string
	RootCAs     *x509.CertPool
	Insecure    bool
	// NoDTLS keeps the data path on the TLS tunnel even where the gateway
	// advertises the UDP channel.
	NoDTLS bool
	// Token is a one-time code to answer a second-factor challenge with. It is
	// good for one login, since that is what a one-time code means.
	Token string
	// TOTPSecret is a base32 shared secret; when set, codes are generated from
	// it as the gateway asks, so a long-running client survives a reconnect that
	// a single Token would not.
	TOTPSecret string
	TUNName    string
	Logger     *slog.Logger
}

// Session is a running Fortinet client.
type Session struct {
	client *ifortinet.Client
}

// Dial authenticates, opens the tunnel, and starts the data path.
func Dial(ctx context.Context, cfg Config) (*Session, client.Result, error) {
	if cfg.Server == "" || cfg.Username == "" {
		return nil, client.Result{}, fmt.Errorf("fortinet: server and user are required")
	}
	logger := vlog.From(cfg.Logger)
	port := cfg.Port
	if port == 0 {
		port = defaultPort
	}
	host := net.JoinHostPort(cfg.Server, strconv.Itoa(port))
	base := "https://" + host

	tlsConfig := &tls.Config{
		ServerName:         cfg.Server,
		MinVersion:         tls.VersionTLS12,
		RootCAs:            cfg.RootCAs,
		InsecureSkipVerify: cfg.Insecure,
	}

	if cfg.Insecure {
		logger.Printf("fortinet: WARNING: server certificate verification disabled (insecure)")
	}

	// Control plane: a cookie-jar client so the SVPNCOOKIE flows to the config
	// fetch.
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, Transport: &http.Transport{TLSClientConfig: tlsConfig, DialContext: cfg.DialContext, Proxy: nil}}
	token, err := tokenFunc(cfg, logger)
	if err != nil {
		return nil, client.Result{}, err
	}
	fcfg, cookie, err := ifortinet.Login(hc, base, cfg.Username, cfg.Password, cfg.Realm, token)
	if err != nil {
		// Both refusals reach the caller as client.ErrAuth, and the second is
		// the one that is easy to get wrong: a gateway demanding a second
		// factor this connection cannot answer has refused the credentials,
		// not failed to be reached, so retrying it with backoff buys nothing
		// and counts against the account's lockout budget just the same.
		return nil, client.Result{}, client.WrapAuth(err, ifortinet.ErrAuth, ifortinet.ErrChallenge)
	}
	if fcfg.AssignedIP == nil {
		return nil, client.Result{}, fmt.Errorf("fortinet: server assigned no address")
	}

	tun, err := dataplane.OpenTUN(cfg.TUNName)
	if err != nil {
		return nil, client.Result{}, fmt.Errorf("fortinet: opening TUN: %w", err)
	}

	c, err := dialDataPath(host, cookie, fcfg, tlsConfig, tun, logger, !cfg.NoDTLS, cfg.DialContext)
	if err != nil {
		_ = tun.Close()
		return nil, client.Result{}, err
	}

	res := client.Result{
		TUNName:    tun.Name(),
		AssignedIP: fcfg.AssignedIP,
		Netmask:    net.IP(net.CIDRMask(defaultMaskBits, 32)),
		// Gateway is the server's OUTER address, so the caller pins a host route to
		// it and the tunnel's own TLS packets do not recurse into it.
		Gateway: outerIP(cfg.Server),
		DNS:     fcfg.DNS,
		MTU:     client.DefaultTunnelMTU,
	}
	logger.Printf("fortinet: tunnel up, assigned %s", fcfg.AssignedIP)
	return &Session{client: c}, res, nil
}

// tokenFunc builds the second-factor answerer from the configuration: a TOTP
// secret generates a code whenever the gateway asks, a literal token answers
// once, and neither means a challenge fails the login rather than hanging on a
// prompt this client has no way to show.
func tokenFunc(cfg Config, logger *vlog.Logger) (ifortinet.TokenFunc, error) {
	if cfg.TOTPSecret != "" {
		secret, err := otp.DecodeSecret(cfg.TOTPSecret)
		if err != nil {
			return nil, fmt.Errorf("fortinet: %s: %w", OptTOTP, err)
		}
		return func(c ifortinet.Challenge) (string, error) {
			if c.Message != "" {
				logger.Printf("fortinet: second factor requested: %s", c.Message)
			}
			return otp.TOTP(secret, time.Now(), otp.Config{})
		}, nil
	}
	if cfg.Token != "" {
		return func(c ifortinet.Challenge) (string, error) {
			if c.Message != "" {
				logger.Printf("fortinet: second factor requested: %s", c.Message)
			}
			return cfg.Token, nil
		}, nil
	}
	return nil, nil
}

// dialDataPath brings the tunnel up: always the TLS tunnel first, then the UDP
// data channel alongside it when the gateway advertises one. That is the order
// the reference client uses and the reason the protocol has a fallback at all —
// the TLS carrier stays open underneath, so a UDP path that fails or later dies
// costs nothing but the datagrams in flight.
func dialDataPath(host, cookie string, fcfg ifortinet.Config, tlsConfig *tls.Config,
	tun io.ReadWriteCloser, logger *vlog.Logger, wantDTLS bool, dial func(context.Context, string, string) (net.Conn, error),
) (*ifortinet.Client, error) {
	c, err := dialTLSPath(host, cookie, fcfg, tlsConfig, tun, logger, dial)
	if err != nil {
		return nil, err
	}
	if !wantDTLS || !fcfg.DTLS {
		return c, nil
	}
	dc, err := dialDTLSChannel(host, cookie, tlsConfig)
	if err != nil {
		logger.Printf("fortinet: DTLS channel unavailable (%v), staying on the TLS tunnel", err)
		return c, nil
	}
	c.AttachDTLS(dc)
	logger.Printf("fortinet: data channel over DTLS")
	return c, nil
}

// dialDTLSChannel opens the UDP data channel and presents the cookie on it.
func dialDTLSChannel(host, cookie string, tlsConfig *tls.Config) (net.Conn, error) {
	// The UDP channel is the same port number as the HTTPS control plane.
	udp, err := net.Dial("udp", host)
	if err != nil {
		return nil, fmt.Errorf("fortinet: dialing DTLS channel: %w", err)
	}
	dc, err := ifortinet.DialDTLS(udp, cookie, tlsConfig)
	if err != nil {
		_ = udp.Close()
		return nil, err
	}
	return dc, nil
}

func dialTLSPath(host, cookie string, fcfg ifortinet.Config, tlsConfig *tls.Config,
	tun io.ReadWriteCloser, logger *vlog.Logger, dial func(context.Context, string, string) (net.Conn, error),
) (*ifortinet.Client, error) {
	var conn *tls.Conn
	var err error
	if dial != nil {
		raw, e := dial(context.Background(), "tcp", host)
		if e != nil {
			return nil, e
		}
		conn = tls.Client(raw, tlsConfig)
		err = conn.Handshake()
		if err != nil {
			conn.Close()
		}
	} else {
		conn, err = tls.Dial("tcp", host, tlsConfig)
	}
	if err != nil {
		return nil, fmt.Errorf("fortinet: dialing tunnel: %w", err)
	}
	if _, err := conn.Write(ifortinet.TunnelRequest(host, cookie)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("fortinet: sending tunnel request: %w", err)
	}
	c, err := ifortinet.RunClient(conn, fcfg, tun, logger)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return c, nil
}

// Probe implements client.Prober.
//
// Fortinet reads as a TLS protocol, which is why it was on the "rides a
// reliable transport, needs nothing here" side of client/liveness.go's split.
// That is true only until DTLS attaches: from then on the UDP carrier is the
// egress and the TLS connection carries nothing, so a UDP path that silently
// stops leaves a healthy TCP connection beside a tunnel that moves no packets.
// The probe is an LCP Echo over whichever carrier is live, so it tests the path
// the data actually takes.
func (s *Session) Probe(ctx context.Context) error { return s.client.Probe(ctx) }

// LivenessConfig implements client.LivenessTuner. An LCP echo is two small
// frames, so it can run often; the tolerance is in MaxFailures, because over
// DTLS a single lost datagram must not read as a dead peer.
func (s *Session) LivenessConfig() client.LivenessConfig {
	return client.LivenessConfig{
		Interval:    10 * time.Second,
		Timeout:     3 * time.Second,
		MaxFailures: 3,
	}
}

// Wait blocks until the session ends or ctx is cancelled.
func (s *Session) Wait(ctx context.Context) error {
	done := make(chan error, 1)
	go func() { done <- s.client.Wait() }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// Close tears the session down.
func (s *Session) Close() error { return s.client.Close() }

// dialer adapts Config to the client registry.
type dialer struct{ cfg Config }

func (d dialer) Dial(ctx context.Context) (client.Session, client.Result, error) {
	return Dial(ctx, d.cfg)
}

// parseOptions turns registry options into a Config.
func parseOptions(opts map[string]string) (client.Dialer, error) {
	cfg := Config{
		Server:     opts[OptServer],
		Username:   opts[OptUser],
		Password:   opts[OptPassword],
		Realm:      opts[OptRealm],
		Insecure:   opts[OptInsecure] == "true",
		NoDTLS:     opts[OptNoDTLS] == "true",
		Token:      opts[OptToken],
		TOTPSecret: opts[OptTOTP],
		TUNName:    opts[OptTUN],
		Logger:     slog.New(vlog.NewTextHandler(os.Stdout, slog.LevelInfo)),
	}
	if cfg.Server == "" {
		return nil, fmt.Errorf("fortinet: server is required")
	}
	if cfg.Username == "" {
		return nil, fmt.Errorf("fortinet: user is required")
	}
	if v := opts[OptPort]; v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p <= 0 || p > 65535 {
			return nil, fmt.Errorf("fortinet: invalid port %q", v)
		}
		cfg.Port = p
	}
	if path := opts[OptCA]; path != "" {
		pem, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("fortinet: reading CA %q: %w", path, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("fortinet: CA %q contains no certificates", path)
		}
		cfg.RootCAs = pool
	}
	return dialer{cfg}, nil
}

// outerIP resolves the server host to an IP for the host route. A resolution
// failure yields nil, which means "install no host route" — acceptable, since
// the name will resolve the same way for the route as for the dial.
func outerIP(host string) net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return ip
	}
	if addrs, err := net.LookupIP(host); err == nil {
		for _, a := range addrs {
			if v4 := a.To4(); v4 != nil {
				return v4
			}
		}
	}
	return nil
}
