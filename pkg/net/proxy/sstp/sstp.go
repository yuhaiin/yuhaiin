// Package sstp is the public entry point for Microsoft's Secure Socket Tunneling
// Protocol (SSTP): TLS/TCP + HTTP CONNECT + PPP (MS-CHAPv2) + crypto binding.
//
// Importing this package registers "sstp" with the client registry:
//
//	import _ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/sstp"
//	sess, res, err := client.Dial(ctx, "sstp", opts)
package sstp

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/sstp/wire"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/dataplane"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/debuglog"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/mschap"
	ppp "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/ppp"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/session"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/vlog"
)

func init() { client.Register("sstp", parseOptions) }

// Option names for client.Dial.
const (
	OptServer   = "server"
	OptPort     = "port"
	OptUser     = "user"
	OptPassword = "password"
	OptTUNName  = "tun"
	OptInsecure = "insecure"
)

// Config holds the parameters for a single SSTP tunnel.
type Config struct {
	DialContext func(context.Context, string, string) (net.Conn, error)
	Server      string
	Port        int
	Username    string
	Password    string
	TUNName     string
	// SkipVerify disables TLS certificate verification. It is safe for SSTP:
	// MS-CHAPv2 mutually authenticates the peers (the client checks the server's
	// authenticator response), so a server that cannot prove it knows the password
	// cannot complete the handshake even without a trusted certificate. Needed for
	// the self-signed certificates most SSTP servers ship with.
	SkipVerify bool
	Logger     *slog.Logger
}

func (c *Config) validate() error {
	if c.Server == "" {
		return fmt.Errorf("sstp: server is required")
	}
	if c.Username == "" || c.Password == "" {
		return fmt.Errorf("sstp: username and password are required")
	}
	return nil
}

func parseOptions(opts map[string]string) (client.Dialer, error) {
	cfg := &Config{}
	if v := opts[OptServer]; v != "" {
		cfg.Server = v
	}
	if v := opts[OptPort]; v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("sstp: invalid port %q", v)
		}
		cfg.Port = p
	}
	cfg.Username = opts[OptUser]
	cfg.Password = opts[OptPassword]
	cfg.TUNName = opts[OptTUNName]
	cfg.SkipVerify = opts[OptInsecure] == "true"
	if cfg.Port == 0 {
		cfg.Port = 443
	}
	return dialer{cfg}, cfg.validate()
}

type dialer struct{ cfg *Config }

func (d dialer) Dial(ctx context.Context) (client.Session, client.Result, error) {
	return Dial(ctx, *d.cfg)
}

// Dial performs the full SSTP handshake, opens a TUN device, and starts the data
// path. It returns a running Session and the Result the caller must apply.
func Dial(ctx context.Context, cfg Config) (client.Session, client.Result, error) {
	if err := cfg.validate(); err != nil {
		return nil, client.Result{}, err
	}
	logger := vlog.From(cfg.Logger)
	if cfg.Logger == nil {
		logger = vlog.Text(debuglog.Writer())
	}

	addr := net.JoinHostPort(cfg.Server, strconv.Itoa(cfg.Port))

	tlsCfg := &tls.Config{
		ServerName:         cfg.Server,
		InsecureSkipVerify: cfg.SkipVerify, //nolint:gosec // opt-in; MS-CHAPv2 mutually authenticates the peers.
	}

	tlsConn, err := dialTLS(ctx, addr, tlsCfg, cfg.DialContext)
	if err != nil {
		return nil, client.Result{}, fmt.Errorf("sstp: TLS dial: %w", err)
	}

	if err := sstpHandshake(tlsConn, cfg.Server); err != nil {
		tlsConn.Close()
		return nil, client.Result{}, fmt.Errorf("sstp: HTTP handshake: %w", err)
	}

	if err := sendCallConnectRequest(tlsConn); err != nil {
		tlsConn.Close()
		return nil, client.Result{}, fmt.Errorf("sstp: CallConnectRequest: %w", err)
	}

	serverNonce, err := readCallConnectAck(tlsConn)
	if err != nil {
		tlsConn.Close()
		return nil, client.Result{}, fmt.Errorf("sstp: CallConnectAck: %w", err)
	}

	s := &session{
		tlsConn:     tlsConn,
		logger:      logger,
		cfg:         cfg,
		serverNonce: serverNonce,
		debug:       debuglog.Enabled(),
		done:        make(chan struct{}),
		ipReady:     make(chan struct{}),
	}
	s.ppp = ppp.New(cfg.Username, cfg.Password, s, s)
	s.ppp.Start()

	go s.readLoop()

	select {
	case <-s.ipReady:
	case <-ctx.Done():
		s.Close()
		return nil, client.Result{}, ctx.Err()
	case <-s.done:
		s.Close()
		// closeErr carries whatever ended the session before IPCP came up. An
		// MS-CHAPv2 refusal is in there, and it is the one the caller must be
		// able to tell apart -- SSTP servers are Windows RRAS and SoftEther,
		// both of which count failed logins.
		return nil, client.Result{}, client.WrapAuth(fmt.Errorf("sstp: %w", s.closeErr), ppp.ErrAuth)
	}

	tun, err := dataplane.OpenTUN(cfg.TUNName)
	if err != nil {
		s.Close()
		return nil, client.Result{}, fmt.Errorf("sstp: open TUN: %w", err)
	}

	s.tun.Store(tun)
	go s.outboundLoop(tun)

	logger.Printf("sstp: tunnel up on %s, internal IP %s, peer %s", tun.Name(), s.assignedIP, s.peerIP)

	res := client.Result{
		TUNName:    tun.Name(),
		AssignedIP: s.assignedIP,
		Netmask:    net.IPv4(255, 255, 255, 255),
		// Gateway is the server's transport IP, kept reachable off-tunnel so the
		// TLS carrier does not recurse into the tunnel (the router pins a host
		// route to it). It is not the PPP peer address.
		Gateway: transportIP(tlsConn),
		DNS:     s.dns,
		MTU:     client.DefaultTunnelMTU,
	}
	return s, res, nil
}

// transportIP returns the server's IP from the established TLS connection, used
// as the off-tunnel host route target.
func transportIP(conn *tls.Conn) net.IP {
	if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return tcp.IP
	}
	return nil
}

func dialTLS(ctx context.Context, addr string, tlsCfg *tls.Config, dial func(context.Context, string, string) (net.Conn, error)) (*tls.Conn, error) {
	if dial != nil {
		raw, err := dial(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		conn := tls.Client(raw, tlsCfg)
		if err := conn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
	d := tls.Dialer{Config: tlsCfg}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return conn.(*tls.Conn), nil
}

type session struct {
	tlsConn     *tls.Conn
	ppp         *ppp.Session
	tun         atomic.Pointer[dataplane.TUN]
	logger      *vlog.Logger
	cfg         Config
	serverNonce []byte
	debug       bool

	// writeMu serializes writes to tlsConn: a TLS connection tolerates one
	// concurrent reader and writer, but the read loop (echo replies, the crypto
	// binding, PPP control) and the outbound loop (data packets) are two writers.
	writeMu sync.Mutex

	mu     sync.Mutex
	closed bool

	closeOnce sync.Once
	closeErr  error
	done      chan struct{}

	assignedIP net.IP
	peerIP     net.IP
	dns        []net.IP
	ipReady    chan struct{}
}

// writePacket sends one already-framed SSTP packet, serialized against the other
// writer and bounded by a write deadline.
func (s *session) writePacket(pkt []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_ = s.tlsConn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	_, err := s.tlsConn.Write(pkt)
	return err
}

func (s *session) SendPPP(frame []byte) error {
	if s.debug {
		s.logger.Printf("sstp: -> ppp %x", frame[:min(len(frame), 12)])
	}
	pkt, err := wire.EncodeData(frame)
	if err != nil {
		return err
	}
	return s.writePacket(pkt)
}

func (s *session) Authenticated(ntResponse [mschap.NTResponseLen]byte) {
	hlak := mschap.ClientHLAK(s.cfg.Password, ntResponse)

	state := s.tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		s.logger.Printf("sstp: no server certificate for crypto binding")
		return
	}
	serverCertDER := state.PeerCertificates[0].Raw

	pkt, err := buildCallConnected(s.serverNonce, serverCertDER, hlak)
	if err != nil {
		s.logger.Printf("sstp: build CallConnected: %v", err)
		return
	}
	if err := s.writePacket(pkt); err != nil {
		s.logger.Printf("sstp: send CallConnected: %v", err)
		return
	}
	s.logger.Printf("sstp: crypto binding sent")
}

func (s *session) NetworkUp(cfg ppp.IPConfig) {
	s.assignedIP = cfg.LocalIP
	s.peerIP = cfg.PeerIP
	s.dns = cfg.DNS
	close(s.ipReady)
}

func (s *session) Closed(err error) { s.fail(err) }

// fail records the first close cause and tears the session down. Only the first
// caller's error is kept, so the true failure (e.g. an auth error) is not
// clobbered by the "use of closed connection" the read loop then observes.
func (s *session) fail(err error) {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		s.closeErr = err
	}
	s.mu.Unlock()
	s.Close()
}

func (s *session) readLoop() {
	for {
		control, body, err := wire.ReadPacket(s.tlsConn)
		if err != nil {
			s.fail(fmt.Errorf("read: %w", err))
			return
		}
		if control {
			msg, err := wire.ParseControl(body)
			if err != nil {
				s.logger.Printf("sstp: malformed control: %v", err)
				continue
			}
			if s.debug {
				s.logger.Printf("sstp: <- control %#x", msg.Type)
			}
			switch msg.Type {
			case wire.MsgCallDisconnect:
				s.fail(fmt.Errorf("server disconnected"))
				return
			case wire.MsgEchoRequest:
				resp, _ := wire.EncodeControl(wire.MsgEchoResponse, nil)
				_ = s.writePacket(resp)
			case wire.MsgCallConnected:
				s.logger.Printf("sstp: server crypto binding ack")
			default:
				s.logger.Printf("sstp: unhandled control %#x", msg.Type)
			}
			continue
		}

		if s.debug {
			s.logger.Printf("sstp: <- ppp %x", body[:min(len(body), 12)])
		}
		// Data packet. Once the link is up its payload is an IP packet bound for the
		// TUN; before that (and for LCP echoes afterwards) it is PPP control.
		if ipPacket, ok := ppp.IsIP(body); ok {
			if tun := s.tun.Load(); tun != nil {
				if _, err := tun.Write(ipPacket); err != nil {
					s.logger.Printf("sstp: TUN write: %v", err)
				}
			}
			continue
		}
		s.ppp.Receive(body)
	}
}

func (s *session) outboundLoop(tun *dataplane.TUN) {
	buf := make([]byte, 65535)
	for {
		n, err := tun.Read(buf)
		if err != nil {
			s.logger.Printf("sstp: TUN read: %v", err)
			s.Close()
			return
		}
		pkt, err := wire.EncodeData(ppp.EncapsulateIP(buf[:n]))
		if err != nil {
			s.logger.Printf("sstp: encode: %v", err)
			continue
		}
		if err := s.writePacket(pkt); err != nil {
			s.logger.Printf("sstp: write: %v", err)
			s.Close()
			return
		}
	}
}

func (s *session) Wait(ctx context.Context) error {
	select {
	case <-s.done:
		return s.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *session) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		if tun := s.tun.Load(); tun != nil {
			_ = tun.Close()
		}
		if s.tlsConn != nil {
			_ = s.tlsConn.Close()
		}
	})
	return s.closeErr
}
