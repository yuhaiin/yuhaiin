package openvpn

// The client: one UDP socket to one server, demultiplexed between the TLS
// control channel and the data channel by opcode (session.go's muxer).
//
//	Dial --> control.Channel --TLS--> key method 2 --> PUSH_REQUEST/REPLY
//	           |                                         |
//	           +-- muxer.readLoop: control --> channel   +--> data.Cipher --> tunnel --> pump
//	                               data    --> pump

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
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

const (
	// handshakeTimeout bounds the whole negotiation: TLS handshake, key exchange
	// and config pull.
	handshakeTimeout = 30 * time.Second
	// controlTimeout is the control-channel retransmit interval (--tls-timeout).
	controlTimeout = 2 * time.Second
	// keepaliveInterval is how often either role sends a data-channel ping to hold
	// the tunnel and NAT binding open.
	keepaliveInterval = 10 * time.Second
	// pingRestart is how long a peer may be silent before it is considered gone.
	// It is the second half of the `ping 10,ping-restart 60` the server pushes:
	// the client is told to restart after 60s of silence, and the server holds
	// itself to the same bound in the other direction. Reaping sooner than the
	// client restarts would tear down a peer that is still trying.
	pingRestart = 60 * time.Second
	// dataTunnelKey is the pump demux key for the client's single data tunnel;
	// the value is arbitrary since there is only one.
	dataTunnelKey = 1
	// defaultMTU is the inner TUN MTU when the server pushes none.
	//
	// It is not derived, and should not be: OpenVPN's own `tun-mtu` default is
	// 1500, and this value is only ever a fallback for a server that declined to
	// push one. Substituting a smaller derived figure would silently disagree
	// with what every other OpenVPN client uses against that same server. The
	// negotiated path is the pushed value, which parseInstruction applies.
	defaultMTU = 1500
)

// Data ciphers the client implements. AES-256-GCM is the default and preferred
// (AEAD, single-pass); AES-256-CBC is the older encrypt-then-MAC path for
// servers that do not offer GCM.
const (
	CipherGCM = "AES-256-GCM"
	CipherCBC = "AES-256-CBC"

	DefaultCipher = CipherGCM
)

// ClientConfig is a client ready to dial: the server resolved, the key
// material read. The public openvpn package builds it from an .ovpn profile and
// options; nothing here parses text. The fields mean what they mean on
// openvpn.Config.
type ClientConfig struct {
	Endpoint *net.UDPAddr

	CA, Cert, Key []byte
	Cipher        string
	Auth          string

	TLSAuth, TLSCrypt []byte
	KeyDirection      int

	Username, Password string

	TUNName string
	Shape   int
	Logger  *vlog.Logger

	PostQuantumOnly bool
}

// AuthError is a negotiation the server ended in a way that says the
// credentials were refused: a TLS alert about the certificate, or the server
// closing the channel at key exchange, which is how OpenVPN rejects a bad
// auth-user-pass. The public package reports it as client.ErrAuth.
type AuthError struct{ Err error }

func (e *AuthError) Error() string { return e.Err.Error() }
func (e *AuthError) Unwrap() error { return e.Err }

// Dial connects to the OpenVPN server, runs the handshake, key exchange and
// config pull, opens the TUN, and starts the data path. It returns a running
// session and the Result the caller must apply. On error nothing is left
// running.
func Dial(ctx context.Context, cfg ClientConfig) (client.Session, client.Result, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = vlog.Discard()
	}

	tlsCfg, err := clientTLSConfig(&cfg)
	if err != nil {
		return nil, client.Result{}, fmt.Errorf("openvpn: %w", err)
	}

	endpoint := cfg.Endpoint
	conn, err := net.DialUDP("udp", nil, endpoint)
	if err != nil {
		return nil, client.Result{}, fmt.Errorf("openvpn: dial %s: %w", endpoint, err)
	}

	wrap, err := buildWrapper(&cfg)
	if err != nil {
		conn.Close()
		return nil, client.Result{}, fmt.Errorf("openvpn: %w", err)
	}

	m := &muxer{conn: conn, logger: logger, closed: make(chan struct{})}
	ch, err := control.New(func(b []byte) error { _, werr := conn.Write(b); return werr }, 0, controlTimeout, wrap)
	if err != nil {
		conn.Close()
		return nil, client.Result{}, fmt.Errorf("openvpn: control channel: %w", err)
	}
	m.control = ch
	go m.readLoop()

	// Bound the whole negotiation; on failure tear the socket down, which unblocks
	// the control channel and the read loop.
	deadline := time.Now().Add(handshakeTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = ch.SetDeadline(deadline)

	result, tunnel, silenceDeadline, err := negotiate(ctx, &cfg, ch, tlsCfg, endpoint, logger)
	if err != nil {
		m.Close()
		if errors.Is(err, io.EOF) || isTLSAuthError(err) {
			return nil, client.Result{}, &AuthError{Err: err}
		}
		return nil, client.Result{}, fmt.Errorf("openvpn: %w", err)
	}
	_ = ch.SetDeadline(time.Time{})

	// GSO: the kernel may hand the pump TCP super-frames to segment and batch
	// (doc/scaling-the-data-path.md); falls back to a plain TUN transparently.
	tun, err := dataplane.OpenTUNGSO(cfg.TUNName)
	if err != nil {
		m.Close()
		return nil, client.Result{}, fmt.Errorf("openvpn: open TUN: %w", err)
	}
	result.TUNName = tun.Name()

	send := func(pkt []byte, _ *net.UDPAddr) {
		if _, werr := conn.Write(pkt); werr != nil {
			logger.Printf("openvpn: send: %v", werr)
		}
	}
	pump := dataplane.NewPump(tun, send, dataDemux, logger.Slog())
	// GSO bursts flush with one sendmmsg on the connected socket. This
	// BatchConn is the pump goroutine's own; the muxer read loop has another.
	sendBC := dataplane.NewBatchConn(conn)
	pump.SetBatchSender(func(pkts [][]byte, _ *net.UDPAddr) {
		if _, werr := sendBC.WriteBatch(pkts, nil); werr != nil {
			logger.Printf("openvpn: batch send: %v", werr)
		}
	})
	pump.SetInnerMTU(result.MTU)
	if cfg.Shape > 0 {
		pump.SetShaper(dataplane.NewShaper(dataplane.ShapeConfig{Bytes: cfg.Shape}))
		logger.Printf("openvpn: upstream shaping on, %d bytes per flow", cfg.Shape)
	}
	pump.AddTunnel(tunnel)
	m.setPump(pump)
	go pump.Run()

	s := &session{
		muxer: m, tun: tun, pump: pump, tunnel: tunnel, conn: conn, logger: logger,
		deadline: silenceDeadline,
		done:     make(chan struct{}),
	}
	go s.keepalive()

	logger.Printf("openvpn: tunnel up on %s, internal IP %s, peer %s", result.TUNName, result.AssignedIP, endpoint)
	return s, result, nil
}

// clientTLSConfig builds the mutual-TLS config: this client's certificate, and
// verification of the server certificate's chain to the CA. OpenVPN does not
// check the server's hostname by default, so neither does this — the CA is the
// trust anchor.
func clientTLSConfig(cfg *ClientConfig) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("client certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cfg.CA) {
		return nil, errors.New("ca: no certificates parsed")
	}
	tlsCfg := &tls.Config{
		Certificates:          []tls.Certificate{cert},
		MinVersion:            tls.VersionTLS12,
		InsecureSkipVerify:    true, // hostname is not verified; the chain check below is
		VerifyPeerCertificate: verifyChainToCA(pool),
	}
	if cfg.PostQuantumOnly {
		// OpenVPN is mutual TLS, so this covers both directions at once: the
		// client's own credential must be ML-DSA, and HardenTLS chains its peer
		// check after verifyChainToCA so the server's must be too.
		if err := pqpolicy.CheckCredential(cert); err != nil {
			return nil, err
		}
		pqpolicy.HardenTLS(tlsCfg)
	}
	return tlsCfg, nil
}

// verifyChainToCA verifies the server certificate chains to the CA, ignoring the
// hostname (which OpenVPN does not bind to the transport address).
func verifyChainToCA(pool *x509.CertPool) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("server sent no certificate")
		}
		certs := make([]*x509.Certificate, len(rawCerts))
		for i, raw := range rawCerts {
			c, err := x509.ParseCertificate(raw)
			if err != nil {
				return err
			}
			certs[i] = c
		}
		opts := x509.VerifyOptions{Roots: pool, Intermediates: x509.NewCertPool()}
		for _, c := range certs[1:] {
			opts.Intermediates.AddCert(c)
		}
		_, err := certs[0].Verify(opts)
		return err
	}
}

// negotiate runs the post-connect handshake over the control channel: TLS, the
// key_method_2 exchange, key derivation, and the config pull. It returns the
// Result (minus the TUN name) and the built data tunnel.
func negotiate(ctx context.Context, cfg *ClientConfig, ch *control.Channel, tlsCfg *tls.Config, endpoint *net.UDPAddr, logger *vlog.Logger) (client.Result, *tunnel, time.Duration, error) {
	tlsConn := tls.Client(ch, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return client.Result{}, nil, 0, fmt.Errorf("tls handshake: %w", err)
	}
	logger.Printf("openvpn: TLS established, negotiating keys")

	// Send our key material, then read the server's and derive data keys.
	clientKS, err := keys.NewClientKeySource()
	if err != nil {
		return client.Result{}, nil, 0, err
	}
	if _, err := tlsConn.Write(clientKS.MarshalClient(occOptions(cfg), cfg.Username, cfg.Password, peerInfo(cfg))); err != nil {
		return client.Result{}, nil, 0, fmt.Errorf("send key material: %w", err)
	}
	serverKS, _, err := readServerKeys(tlsConn)
	if err != nil {
		return client.Result{}, nil, 0, fmt.Errorf("read server key material: %w", err)
	}

	clientSID := keys.SessionID(ch.LocalSessionID())
	remoteSID, _ := ch.RemoteSessionID()
	serverSID := keys.SessionID(remoteSID)
	ks2 := &keys.KeySource2{Client: *clientKS, Server: *serverKS}

	// Pull the pushed configuration.
	if _, err := tlsConn.Write([]byte("PUSH_REQUEST\x00")); err != nil {
		return client.Result{}, nil, 0, fmt.Errorf("push request: %w", err)
	}
	reply, err := readPushReply(tlsConn)
	if err != nil {
		return client.Result{}, nil, 0, fmt.Errorf("read push reply: %w", err)
	}
	logger.Printf("openvpn: server pushed %q", reply)

	pushed, err := parsePush(reply)
	if err != nil {
		return client.Result{}, nil, 0, err
	}

	// The server's pushed cipher is authoritative under NCP; if it pushes none,
	// fall back to the configured cipher (an old server using its compiled --cipher).
	effectiveCipher := cfg.Cipher
	if pushed.cipher != "" {
		effectiveCipher = pushed.cipher
	}
	dc, err := buildDataCipher(effectiveCipher, cfg, ks2, clientSID, serverSID, pushed.peerID)
	if err != nil {
		return client.Result{}, nil, 0, err
	}
	logger.Printf("openvpn: data channel cipher %s", effectiveCipher)
	routes := []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0)}
	if pushed.localIP6 != nil {
		// The pump's route trie is per-family, so a v4 default route matches no
		// v6 packet. Without this the interface would carry a v6 address and
		// drop every packet sent from it, which reads as a routing problem on
		// the host and is not one.
		routes = append(routes, netip.PrefixFrom(netip.IPv6Unspecified(), 0))
	}
	tun := &tunnel{
		cipher: dc,
		routes: routes,
	}
	tun.peer.Store(endpoint)

	res := client.Result{
		AssignedIP:  pushed.localIP,
		Netmask:     pushed.netmask,
		AssignedIP6: pushed.localIP6,
		Prefix6:     pushed.prefix6,
		// Gateway is the server's real transport IP: the client router pins a host
		// route to it via the physical gateway so the encapsulated packets do not
		// loop back into the tunnel. The pushed route-gateway is the tunnel's
		// internal address and must not be used here — it would collide with
		// in-tunnel destinations.
		Gateway: endpoint.IP,
		MTU:     pushed.mtu,
	}
	return res, tun, livenessDeadline(pushed), nil
}

// readServerKeys reads TLS bytes until a complete server key_method_2 message is
// present, then parses it.
func readServerKeys(tlsConn *tls.Conn) (*keys.KeySource, string, error) {
	buf := make([]byte, 0, 512)
	tmp := make([]byte, 4096)
	for {
		n, err := tlsConn.Read(tmp)
		if err != nil {
			return nil, "", err
		}
		buf = append(buf, tmp[:n]...)
		ks, opts, perr := keys.ParseServer(buf)
		if perr == nil {
			return ks, opts, nil
		}
		if !errors.Is(perr, keys.ErrShortMessage) {
			return nil, "", perr
		}
		if len(buf) > 8192 {
			return nil, "", errors.New("server key message too long")
		}
	}
}

// readPushReply reads TLS bytes until a NUL-terminated control string arrives.
func readPushReply(tlsConn *tls.Conn) (string, error) {
	buf := make([]byte, 0, 512)
	tmp := make([]byte, 4096)
	for {
		n, err := tlsConn.Read(tmp)
		if err != nil {
			return "", err
		}
		buf = append(buf, tmp[:n]...)
		if before, _, found := bytes.Cut(buf, []byte{0}); found {
			return string(before), nil
		}
		if len(buf) > 16384 {
			return "", errors.New("push reply too long")
		}
	}
}

// buildDataCipher constructs the data-channel crypto for the negotiated cipher,
// deriving the matching key material. The GCM path is the AEAD default; the CBC
// path derives an HMAC key of the --auth digest's size.
func buildDataCipher(name string, cfg *ClientConfig, ks2 *keys.KeySource2, clientSID, serverSID keys.SessionID, peerID uint32) (dataCipher, error) {
	switch {
	case strings.EqualFold(name, CipherGCM):
		dk := ks2.Derive(clientSID, serverSID, false)
		return data.New(dk, peerID, 0)
	case strings.EqualFold(name, CipherCBC):
		digest, err := tlswrap.ParseDigest(cfg.Auth)
		if err != nil {
			return nil, fmt.Errorf("cbc data channel: %w", err)
		}
		ck := ks2.DeriveCBC(clientSID, serverSID, false)
		return data.NewCBC(ck, digest.New, digest.Size, peerID, 0)
	default:
		return nil, fmt.Errorf("server negotiated unsupported cipher %q", name)
	}
}

// occOptions is the OCC options string. Without --opt-verify on the server it is
// advisory, so a plausible value suffices; the cipher and auth fields track the
// configured data channel.
func occOptions(cfg *ClientConfig) string {
	authName := "[null-digest]" // GCM authenticates within the AEAD
	if strings.EqualFold(cfg.Cipher, CipherCBC) {
		authName = strings.ToUpper(digestName(cfg.Auth))
	}
	return fmt.Sprintf("V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,cipher %s,auth %s,keysize 256,key-method 2,tls-client",
		strings.ToUpper(cfg.Cipher), authName)
}

// peerInfo advertises this client's capabilities: P_DATA_V2 support (IV_PROTO
// bit 1) so the server assigns a peer-id, NCP, and the configured data cipher, so
// the server negotiates it.
func peerInfo(cfg *ClientConfig) string {
	return fmt.Sprintf("IV_VER=2.6.0\nIV_PROTO=2\nIV_NCP=2\nIV_CIPHERS=%s\n", strings.ToUpper(cfg.Cipher))
}

// digestName returns the --auth digest name, defaulting to SHA1 (OpenVPN's
// default) when unset.
func digestName(auth string) string {
	if auth == "" {
		return "SHA1"
	}
	return auth
}

// isTLSAuthError reports whether an error is a TLS certificate verification
// failure, so dial can map it to client.ErrAuth.
func isTLSAuthError(err error) bool {
	var ce *tls.CertificateVerificationError
	return errors.As(err, &ce)
}

// buildWrapper builds the control-channel protection from the config: --tls-crypt
// (encrypt + authenticate) takes precedence over --tls-auth (authenticate only),
// and neither yields a nil wrapper — the plain control channel.
func buildWrapper(cfg *ClientConfig) (control.Wrapper, error) {
	switch {
	case len(cfg.TLSCrypt) > 0:
		key, err := tlswrap.ParseStaticKey(cfg.TLSCrypt)
		if err != nil {
			return nil, fmt.Errorf("tls-crypt key: %w", err)
		}
		// tls-crypt's client direction is fixed: it sends with the second key slot
		// and receives with the first.
		return tlswrap.NewCrypt(key, tlswrap.Inverse)
	case len(cfg.TLSAuth) > 0:
		key, err := tlswrap.ParseStaticKey(cfg.TLSAuth)
		if err != nil {
			return nil, fmt.Errorf("tls-auth key: %w", err)
		}
		digest, err := tlswrap.ParseDigest(cfg.Auth)
		if err != nil {
			return nil, fmt.Errorf("tls-auth: %w", err)
		}
		return tlswrap.NewAuth(key, authDirection(cfg.KeyDirection), digest), nil
	default:
		return nil, nil
	}
}

// authDirection maps a --key-direction (0, 1, or -1 for unset) to the tlswrap
// direction the client sends and receives with.
func authDirection(keyDirection int) tlswrap.Direction {
	switch keyDirection {
	case 0:
		return tlswrap.Normal
	case 1:
		return tlswrap.Inverse
	default:
		return tlswrap.Bidirectional
	}
}

// dataDemux routes any data-channel packet to the client's single tunnel.
func dataDemux(pkt []byte) (uint32, bool) {
	op, _, ok := wire.Opcode(pkt)
	if !ok || !data.IsDataOpcode(op) {
		return 0, false
	}
	return dataTunnelKey, true
}
