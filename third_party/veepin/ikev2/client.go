// Package ikev2 is the public entry point to this module's IKEv2
// implementation: a client that performs the handshake (PSK or EAP-MSCHAPv2)
// and runs a userspace ESP-in-UDP data path over a TUN device.
//
// Like every protocol here, Dial installs no addresses, routes or DNS. It
// returns the negotiated client.Result and the caller applies it — the veepin
// command hands it to dataplane's router, and the NetworkManager plugin hands it
// to NM.
//
// Importing this package also registers "ikev2" with the client registry, so a
// caller that dials by name only needs the blank import:
//
//	import _ "github.com/xen0bit/veepin/ikev2"
//
//	sess, res, err := client.Dial(ctx, "ikev2", opts)
//
// The protocol internals (the state machine, wire codec, ESP and EAP) stay in
// internal/ikev2; this package is the supported surface.
package ikev2

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/ikev2/ike"
	"github.com/xen0bit/veepin/internal/pqpolicy"
	"github.com/xen0bit/veepin/internal/vlog"
)

func init() { client.Register("ikev2", parseOptions) }

// Config describes how to reach and authenticate to an IKEv2 server.
type Config struct {
	DialContext func(context.Context, string, string) (net.Conn, error)
	// Server is the VPN server host or IP (required).
	Server string
	// Port is the server IKE port (default 500).
	Port int

	// PSK authenticates the server, and the client too unless EAP is used
	// (required).
	PSK string
	// LocalID is the identity presented to the server, e.g. "client.example.com"
	// or an IP literal (required).
	LocalID string
	// ServerID, if set, is verified against the server's presented identity.
	ServerID string

	// EAPUser/EAPPassword, if set, switch client authentication to
	// EAP-MSCHAPv2. The server still authenticates itself with the PSK.
	EAPUser     string
	EAPPassword string

	// CertFile/KeyFile, if set, authenticate the client with an X.509
	// certificate (RFC 7427 digital signature) instead of the PSK. CAFile is the
	// PEM bundle used to verify the server's certificate; empty uses the host's
	// system roots.
	CertFile string
	KeyFile  string
	CAFile   string

	// TUNName is the desired TUN interface name; empty lets the kernel pick.
	TUNName string

	// PostQuantum offers ML-KEM-768 as an additional key exchange (RFC 9370),
	// carried in an IKE_INTERMEDIATE exchange (RFC 9242). The result is hybrid:
	// the classical group still runs and still contributes. A server that does
	// not support it is not an error — the handshake proceeds classically.
	PostQuantum bool

	// PostQuantumOnly additionally requires the responder to authenticate with
	// an ML-DSA certificate. It is what the pq-ikev2 registry name sets, and it
	// implies PostQuantum.
	PostQuantumOnly bool

	// IPTFS enables AGGFRAG aggregation and fragmentation (RFC 9347) for the
	// Child SA. When set, the client advertises USE_AGGFRAG in IKE_AUTH and
	// uses ESP Next Header 144 instead of the usual 4/41.
	IPTFS bool
	// IPTFSRate is the constant-rate transmission target in bytes/sec. Zero
	// means aggregation-only (no constant-rate shaping); the data path fills
	// each ESP packet to the MTU with whatever inner traffic is available.
	IPTFSRate int

	// RekeyInterval is the Child SA soft lifetime: the client proactively
	// rekeys the ESP SA (a CREATE_CHILD_SA exchange, new keys, old SA deleted)
	// this often, so a long-lived tunnel never lets its data SA expire. Zero
	// uses defaultRekeyInterval; negative disables proactive rekey.
	RekeyInterval time.Duration

	// IKERekeyInterval is the IKE SA soft lifetime: the client proactively
	// rekeys the IKE SA itself (RFC 7296 2.18 — a fresh DH exchange for a new
	// control channel, the Child SAs inherited unchanged, the old SA deleted)
	// this often. Zero uses defaultIKERekeyInterval; negative disables it.
	IKERekeyInterval time.Duration

	// TCP carries IKE and ESP over one TCP connection instead of UDP (RFC 8229,
	// updated by RFC 9329), for a network that blocks UDP. RFC 8229 section 3
	// has no port-500 phase, so Port names the TCP port directly and defaults
	// to 4500 — the one knob that changes meaning, and the useful one, since a
	// network that blocks UDP often only permits 443.
	//
	// It is "use TCP", not "prefer TCP": there is no fallback to UDP, because
	// the deployments this exists for are exactly the ones where UDP does not
	// work, and a silent fallback there is a tunnel that cannot come up
	// pretending it might.
	TCP bool

	// Shape enables shaping of this client's *upstream* traffic: how much padded
	// output each inner flow is given before shaping stops for that flow, so it
	// bounds what shaping costs. Zero, the default, disables it.
	//
	// The server shapes the downstream direction, which is where the larger
	// half of an inner TLS handshake sits and which a stock client gets for
	// free (see dataplane/shape.go). This covers the other half, and so only
	// applies when both ends are veepin.
	Shape int

	// Logger receives progress logs; nil discards them.
	Logger *slog.Logger
}

// defaultRekeyInterval is the Child SA soft lifetime when Config.RekeyInterval
// is zero. IKEv2 does not negotiate lifetimes (RFC 7296), so this is local
// policy; one hour is a conservative default well under common byte ceilings.
const defaultRekeyInterval = time.Hour

// defaultIKERekeyInterval is the IKE SA soft lifetime when
// Config.IKERekeyInterval is zero. It is longer than the Child SA lifetime —
// the IKE SA carries only control traffic, so it ages far more slowly — and
// mirrors the common strongSwan default of a few hours.
const defaultIKERekeyInterval = 4 * time.Hour

// defaultNATTPort is the port RFC 3948 NAT-T floats to and the one RFC 8229
// TCP encapsulation uses from the first octet. It is named here because the
// TCP path has no other port to speak of.
const defaultNATTPort = 4500

// Option keys accepted by client.Dial(ctx, "ikev2", opts). They match the
// NetworkManager plugin's connection settings, which is why the parsed names are
// hyphenated rather than Go-cased.
const (
	OptGateway   = "gateway"      // server host or IP (required)
	OptPort      = "port"         // server IKE port (default 500)
	OptPSK       = "psk"          // pre-shared key (required)
	OptLocalID   = "local-id"     // identity presented to the server (required)
	OptServerID  = "server-id"    // expected server identity (optional)
	OptUser      = "user"         // EAP-MSCHAPv2 username (optional)
	OptPassword  = "password"     // EAP-MSCHAPv2 password (optional)
	OptTUNName   = "tun"          // desired TUN interface name (optional)
	OptRekey     = "rekey"        // Child SA rekey interval in seconds (optional)
	OptIKERekey  = "ike-rekey"    // IKE SA rekey interval in seconds (optional)
	OptCert      = "cert"         // client certificate PEM path (enables certificate auth)
	OptKey       = "key"          // client private-key PEM path
	OptCA        = "ca"           // CA bundle PEM path to verify the server (optional)
	OptShape     = "shape"        // per-flow upstream shaping budget in bytes (0 = off)
	OptPQ        = "post-quantum" // offer ML-KEM-768 as an additional key exchange
	OptIPTFS     = "iptfs"        // enable AGGFRAG (IP-TFS) aggregation (RFC 9347)
	OptIPTFSRate = "iptfs-rate"   // constant-rate IP-TFS in bytes/sec; 0 = aggregation only
	OptTCP       = "tcp"          // carry IKE and ESP over TCP (RFC 8229/9329) instead of UDP
)

// parseOptions turns string-keyed options into a Dialer. It is what the registry
// calls for client.Dial(ctx, "ikev2", opts).
func parseOptions(opts map[string]string) (client.Dialer, error) {
	// The deprecation, said once and where the operator will see it. -pq only
	// ever OFFERED ML-KEM and fell back silently when the responder declined,
	// which is the downgrade the pq-ikev2 name exists to close. Warnf rather
	// than Printf so it survives -log-level warn: a line telling somebody their
	// post-quantum protection is optional should not be hidden at the level
	// they turned logging down to.
	if opts[OptPQ] == "true" && !pqpolicy.Requested(opts) {
		vlog.Text(os.Stdout).Warnf("ikev2: -pq is deprecated and will be removed. It OFFERS " +
			"ML-KEM-768 and silently accepts a classical SA if the responder declines. " +
			"Use `veepin connect pq-ikev2`, which refuses instead.")
	}
	cfg := Config{
		Server:          opts[OptGateway],
		PSK:             opts[OptPSK],
		LocalID:         opts[OptLocalID],
		ServerID:        opts[OptServerID],
		EAPUser:         opts[OptUser],
		EAPPassword:     opts[OptPassword],
		TUNName:         opts[OptTUNName],
		CertFile:        opts[OptCert],
		KeyFile:         opts[OptKey],
		CAFile:          opts[OptCA],
		PostQuantum:     opts[OptPQ] == "true" || pqpolicy.Requested(opts),
		PostQuantumOnly: pqpolicy.Requested(opts),
		IPTFS:           opts[OptIPTFS] == "true",
		TCP:             opts[OptTCP] == "true",
		// Without this the engine's log goes nowhere: Dial discards a nil
		// Logger, so every line internal/ikev2/ike writes -- AGGFRAG
		// negotiated or declined, a rekey, a MOBIKE roam, a certificate
		// warning -- was dropped on the floor for every dial through the
		// registry, which is every dial `veepin connect ikev2` makes. The
		// server half has always wired one (server.go); the client half never
		// did, and nothing failed, because a discarded log looks exactly like
		// a quiet protocol.
		//
		// It is also what makes an IKEv2 interop cell able to use
		// runInteropRequiringLog. Without a log there is no way to assert that
		// a negotiated option actually came up, and a ping passes just as
		// happily on the fallback -- which for IP-TFS is strongSwan silently
		// dropping to plain tunnel mode.
		Logger: slog.New(vlog.NewTextHandler(os.Stdout, slog.LevelInfo)),
	}
	if v := opts[OptIPTFSRate]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("bad %s %q", OptIPTFSRate, v)
		}
		cfg.IPTFSRate = n
	}
	if p := opts[OptPort]; p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("bad %s %q: %w", OptPort, p, err)
		}
		cfg.Port = n
	}
	if r := opts[OptRekey]; r != "" {
		n, err := strconv.Atoi(r)
		if err != nil {
			return nil, fmt.Errorf("bad %s %q: %w", OptRekey, r, err)
		}
		cfg.RekeyInterval = time.Duration(n) * time.Second
	}
	if r := opts[OptIKERekey]; r != "" {
		n, err := strconv.Atoi(r)
		if err != nil {
			return nil, fmt.Errorf("bad %s %q: %w", OptIKERekey, r, err)
		}
		cfg.IKERekeyInterval = time.Duration(n) * time.Second
	}
	if v := opts[OptShape]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("bad %s %q", OptShape, v)
		}
		cfg.Shape = n
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return dialer{cfg}, nil
}

func (cfg Config) validate() error {
	switch {
	case cfg.Server == "":
		return fmt.Errorf("%s is required", OptGateway)
	case cfg.LocalID == "":
		return fmt.Errorf("%s is required", OptLocalID)
	case cfg.CertFile != "" && cfg.KeyFile == "":
		return fmt.Errorf("%s requires %s", OptCert, OptKey)
	case cfg.CertFile == "" && cfg.PSK == "":
		// Without a certificate the PSK is what authenticates the server (and the
		// client, unless EAP is used).
		return fmt.Errorf("%s is required unless %s is set", OptPSK, OptCert)
	case cfg.IPTFSRate > 0 && !cfg.IPTFS:
		return fmt.Errorf("%s needs %s: there is no constant-rate transmission "+
			"without the AGGFRAG data path to carry it", OptIPTFSRate, OptIPTFS)
	case cfg.IPTFSRate > 0 && cfg.Shape > 0:
		// Refused rather than ignored. The paced data path does not go through
		// the shaper at all, so accepting both would mean -shape silently did
		// nothing -- the same shape of bug as -kill-switch under -no-route,
		// which this tree has already had once.
		//
		// It is also not a loss. Constant-rate transmission fixes every
		// datagram at one size, which is what -shape pads *towards*; there is
		// nothing left for it to do.
		return fmt.Errorf("%s and %s cannot both be set: constant-rate transmission "+
			"already fixes every datagram at one size, so %s would have nothing to pad",
			OptShape, OptIPTFSRate, OptShape)
	}
	return nil
}

// nattPort is the port ESP (and, over TCP, the whole exchange) runs on.
//
// Over UDP it is fixed at 4500: RFC 3948 defines the float and Config.Port
// names the port-500 phase, which is a different thing. Over TCP there is no
// float and no port-500 phase, so Config.Port names this port instead.
func nattPort(cfg Config) int {
	if cfg.TCP && cfg.Port != 0 {
		return cfg.Port
	}
	return defaultNATTPort
}

// dialer adapts a Config to client.Dialer.
type dialer struct{ cfg Config }

func (d dialer) Dial(ctx context.Context) (client.Session, client.Result, error) {
	return Dial(ctx, d.cfg)
}

// Dial performs the handshake, opens the TUN, and starts the ESP data path,
// returning a running session and the Result the caller must apply. It installs
// no routes or addresses. On error nothing is left running.
//
// The context bounds the setup; once Dial returns, use the session's Wait/Close
// for the tunnel lifetime.
func Dial(ctx context.Context, cfg Config) (client.Session, client.Result, error) {
	if err := cfg.validate(); err != nil {
		return nil, client.Result{}, fmt.Errorf("ikev2: %w", err)
	}
	logger := vlog.From(cfg.Logger)

	ikeCfg := ike.ClientConfig{
		ServerHost:      cfg.Server,
		ServerPort:      cfg.Port,
		NATTPort:        nattPort(cfg),
		PSK:             []byte(cfg.PSK),
		LocalID:         parseIdentity(cfg.LocalID),
		EAPUsername:     cfg.EAPUser,
		EAPPassword:     cfg.EAPPassword,
		PostQuantum:     cfg.PostQuantum || cfg.PostQuantumOnly,
		PostQuantumAuth: cfg.PostQuantumOnly,
		IPTFS:           cfg.IPTFS,
		IPTFSRate:       cfg.IPTFSRate,
		TCP:             cfg.TCP,
		DialContext:     cfg.DialContext,
		Logger:          logger,
	}
	if cfg.ServerID != "" {
		id := parseIdentity(cfg.ServerID)
		ikeCfg.RemoteID = &id
	}
	if cfg.CertFile != "" {
		cert, err := loadTLSCert(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, client.Result{}, fmt.Errorf("ikev2: client certificate: %w", err)
		}
		ikeCfg.ClientCert = cert
		if cfg.CAFile != "" {
			pool, err := loadCAPool(cfg.CAFile)
			if err != nil {
				return nil, client.Result{}, fmt.Errorf("ikev2: CA bundle: %w", err)
			}
			ikeCfg.CARoots = pool
		}
	}

	// 1. Handshake, honoring ctx cancellation. Connect has its own read
	// deadlines, but a caller (e.g. an NM Disconnect mid-handshake) must be able
	// to abort promptly rather than wait them out.
	c := ike.NewClient(ikeCfg)
	res, err := connect(ctx, c)
	if err != nil {
		return nil, client.Result{}, client.WrapAuth(
			fmt.Errorf("ikev2: connect: %w", err), ike.ErrAuthFailed)
	}
	// From here on, any failure must close the IKE client.
	fail := func(err error) (client.Session, client.Result, error) {
		c.Close()
		return nil, client.Result{}, err
	}

	// Switch the IKE client to post-handshake control mode: the data-path read
	// loop below now owns the socket, so it delivers received IKE datagrams
	// (DPD responses, rekey, peer deletes) to the client instead of the client
	// reading them inline. This is what lets Probe run dead-peer detection.
	c.Attach()

	// 2. TUN.
	tun, err := dataplane.OpenTUNGSO(cfg.TUNName)
	if err != nil {
		return fail(fmt.Errorf("ikev2: open TUN: %w", err))
	}

	// 3. Data-path tunnel.
	tunnel, err := res.BuildTunnel()
	if err != nil {
		tun.Close()
		return fail(fmt.Errorf("ikev2: build tunnel: %w", err))
	}

	// 4. ESP shares the IKE transport. Over UDP that is the IKE socket (already
	// floated to NAT-T port 4500), so ESP and IKE leave from one source port —
	// the standards-compliant NAT-T layout a responder relies on to route return
	// ESP back to us. Over TCP (RFC 8229/9329) it is the one stream, carrying
	// both length-prefixed. Exactly one of DataConn and DataStream is non-nil.
	stream := c.DataStream()
	if stream != nil {
		// Named in the log because it is the one thing a ping cannot tell you.
		// A tunnel that quietly came up over UDP pings exactly as well as one
		// that used the stream, and the whole point of this transport is the
		// network where the first is impossible.
		logger.Printf("ikev2: IKE and ESP ride one RFC 8229 TCP stream to %s", stream.RemoteAddr())
	}

	s := &session{
		ike:          c,
		tun:          tun,
		logger:       logger,
		tunnel:       tunnel,
		stream:       stream,
		childInSPI:   res.InboundSPI,
		done:         make(chan struct{}),
		stopKA:       make(chan struct{}),
		stopRekey:    make(chan struct{}),
		stopIKERekey: make(chan struct{}),
	}

	var (
		send      dataplane.Sender
		batchSend func(pkts [][]byte, to *net.UDPAddr)
	)
	if stream != nil {
		// The stream is the destination, so the peer address the pump passes is
		// ignored — as it is on the connected UDP socket below, for the same
		// reason.
		send = func(esp []byte, _ *net.UDPAddr) {
			if werr := stream.WriteESP(esp); werr != nil && !s.closing.Load() {
				logger.Warnf("ikev2: ESP send error: %v", werr)
			}
		}
		// A stream has no datagram boundary to preserve, so a GSO burst becomes
		// ONE write carrying several frames — the stream's answer to sendmmsg,
		// and the reason the batch sender is wired here rather than dropped.
		batchSend = func(pkts [][]byte, _ *net.UDPAddr) {
			if werr := stream.WriteESPBatch(pkts); werr != nil && !s.closing.Load() {
				logger.Warnf("ikev2: ESP batch send error: %v", werr)
			}
		}
	} else {
		dataConn := c.DataConn()
		// The ESP socket is held behind an atomic so MOBIKE Roam can swap it
		// under the running data path (see session.Roam).
		s.conn.Store(dataConn)
		s.sendBC.Store(dataplane.NewBatchConn(dataConn))
		// The socket is connected to the server, so the destination is implicit.
		send = func(esp []byte, _ *net.UDPAddr) {
			if _, werr := s.conn.Load().Write(esp); werr != nil && !s.roaming.Load() {
				logger.Warnf("ikev2: ESP send error: %v", werr)
			}
		}
		// GSO bursts flush with one sendmmsg on the connected socket, via the
		// swappable BatchConn.
		batchSend = func(pkts [][]byte, _ *net.UDPAddr) {
			if _, werr := s.sendBC.Load().WriteBatch(pkts, nil); werr != nil && !s.roaming.Load() {
				logger.Warnf("ikev2: ESP batch send error: %v", werr)
			}
		}
	}

	// The tunnel reports 0.0.0.0/0 as its route, so everything leaving the TUN is
	// routed to the server; no separate default-route call is needed.
	pump := dataplane.NewPump(tun, send, dataplane.SPIDemux, logger.Slog())
	if cfg.Shape > 0 {
		pump.SetShaper(dataplane.NewShaper(dataplane.ShapeConfig{Bytes: cfg.Shape}))
		logger.Printf("ikev2: upstream shaping on, %d bytes per flow", cfg.Shape)
	}
	pump.SetBatchSender(batchSend)
	pump.AddTunnel(tunnel)
	s.pump = pump
	go pump.Run()

	if stream != nil {
		go s.readStream(pump)
	} else {
		go s.readSocket(pump)
		// NAT keepalive: a single 0xFF byte every 20s holds the NAT binding
		// (RFC 3948). There is no such thing over TCP — the connection is the
		// binding, and the kernel's own TCP keepalive holds it.
		go func() {
			t := time.NewTicker(20 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-s.stopKA:
					return
				case <-t.C:
					_, _ = s.conn.Load().Write([]byte{0xff})
				}
			}
		}()
	}

	// Proactive Child SA rekey: replace the ESP SA before its soft lifetime so a
	// long-lived tunnel never lets its data SA expire.
	rekeyEvery := cfg.RekeyInterval
	if rekeyEvery == 0 {
		rekeyEvery = defaultRekeyInterval
	}
	if rekeyEvery > 0 {
		go func() {
			t := time.NewTicker(rekeyEvery)
			defer t.Stop()
			for {
				select {
				case <-s.stopRekey:
					return
				case <-t.C:
					if err := s.rekeyChild(); err != nil {
						// A failed rekey leaves the current SA in place; the next
						// tick retries. Liveness (Probe) catches a truly dead peer.
						logger.Warnf("ikev2: Child SA rekey failed: %v", err)
					}
				}
			}
		}()
	}

	// Proactive IKE SA rekey: rotate the control channel itself (fresh DH, new
	// SK_* keys) before its soft lifetime, with the Child SAs inherited so the
	// data path never pauses.
	ikeRekeyEvery := cfg.IKERekeyInterval
	if ikeRekeyEvery == 0 {
		ikeRekeyEvery = defaultIKERekeyInterval
	}
	if ikeRekeyEvery > 0 {
		go func() {
			t := time.NewTicker(ikeRekeyEvery)
			defer t.Stop()
			for {
				select {
				case <-s.stopIKERekey:
					return
				case <-t.C:
					if err := s.rekeyIKE(); err != nil {
						// A failed IKE rekey leaves the current SA in place; the
						// next tick retries. Liveness catches a truly dead peer.
						logger.Warnf("ikev2: IKE SA rekey failed: %v", err)
					}
				}
			}
		}()
	}

	out := client.Result{
		TUNName:     tun.Name(),
		AssignedIP:  res.AssignedIP,
		Netmask:     res.Netmask,
		AssignedIP6: res.AssignedIP6,
		Prefix6:     res.Prefix6,
		Gateway:     serverGateway(res, cfg.Server),
		DNS:         res.DNS,
		MTU:         client.DefaultTunnelMTU,
	}
	logger.Printf("ikev2: tunnel up on %s, internal IP %s / %s, DNS %v",
		out.TUNName, out.AssignedIP, out.AssignedIP6, out.DNS)
	return s, out, nil
}

// session is a running IKEv2 tunnel: the IKE SA, the TUN device, and the ESP
// pump. It implements client.Session.
type session struct {
	ike  *ike.Client
	tun  *dataplane.TUN
	pump *dataplane.Pump
	// conn is the IKE socket (floated to 4500), shared for the ESP data path so
	// ESP and IKE share one source port as RFC 3948 NAT-T requires. It is held
	// atomically because MOBIKE Roam swaps it under the running data path; it is
	// owned by ike, and Close closes the current one via ike.Close().
	conn   atomic.Pointer[net.UDPConn]
	sendBC atomic.Pointer[dataplane.BatchConn]
	// stream is the RFC 8229/9329 TCP transport when this SA runs over TCP, and
	// nil otherwise. It is not atomic because nothing swaps it: MOBIKE does not
	// apply to a stream — the connection IS the address binding, so an address
	// change breaks it and the answer is to reconnect.
	stream *ike.TCPStream
	logger *vlog.Logger

	roamMu  sync.Mutex  // serializes Roam
	roaming atomic.Bool // a socket swap is in progress
	closing atomic.Bool // Close was called; read-loop errors are terminal

	// rekeyMu guards the Child SA data-path swap: tunnel and childInSPI track the
	// currently-installed ESP SA so a rekey can retire exactly the SA it
	// replaced. Only the rekey goroutine writes them, under the lock.
	rekeyMu    sync.Mutex
	tunnel     dataplane.Tunnel
	childInSPI uint32

	closeOnce    sync.Once
	closeErr     error
	done         chan struct{} // closed when the inbound loop exits (i.e. on Close)
	stopKA       chan struct{} // stops the NAT-keepalive goroutine
	stopRekey    chan struct{} // stops the proactive Child-SA-rekey goroutine
	stopIKERekey chan struct{} // stops the proactive IKE-SA-rekey goroutine
}

// readSocket is the inbound loop for a UDP-transported SA: ESP and any late IKE
// arrive on the shared NAT-T socket. It exits when the socket is closed (on
// Close, via ike.Close()). A 4-zero-octet prefix marks a non-ESP datagram (NAT
// keepalive, or IKE); everything else is ESP. Reads are batched
// (dataplane.BatchConn over the connected socket): one recvmmsg drains up to
// readBatch datagrams under load and blocks like a plain read when idle.
func (s *session) readSocket(pump *dataplane.Pump) {
	defer close(s.done)
	const readBatch = 16
	bufs := make([][]byte, readBatch)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	sizes := make([]int, readBatch)
	esps := make([][]byte, 0, readBatch)
	// bc wraps the current socket; it is rebuilt whenever a MOBIKE Roam swaps
	// the socket (s.conn changes).
	var bc *dataplane.BatchConn
	var bcConn *net.UDPConn
	for {
		if conn := s.conn.Load(); conn != bcConn {
			bc = dataplane.NewBatchConn(conn)
			bcConn = conn
		}
		n, rerr := bc.ReadBatch(bufs, sizes)
		esps = esps[:0]
		for i := range n {
			pkt := bufs[i][:sizes[i]]
			if len(pkt) >= 4 && pkt[0] == 0 && pkt[1] == 0 && pkt[2] == 0 && pkt[3] == 0 {
				// Non-ESP: a NAT keepalive (single 0xFF, too short) or an IKE
				// control message (DPD response, rekey, peer delete). Hand any
				// IKE message to the control channel; drop keepalives. Copied
				// out because the exchange may outlive this batch's buffer.
				if len(pkt) > 4 {
					ike := make([]byte, len(pkt)-4)
					copy(ike, pkt[4:])
					s.ike.Deliver(ike)
				}
				continue
			}
			// Collected without a copy: the whole batch goes to the pump at
			// once so inbound TCP can coalesce (GRO); the pump decrypts in
			// place and writes the TUN before returning — bufs[i] is not
			// touched again until the next ReadBatch. Connected socket: the
			// source is implicitly the server (froms nil).
			esps = append(esps, pkt)
		}
		if len(esps) > 0 {
			pump.HandleInboundBatch(esps, nil)
		}
		if rerr != nil {
			if s.closing.Load() {
				return
			}
			// A read error during a Roam is the old socket being closed as the
			// SA relocates. Wait for the new socket to be published, then keep
			// reading it rather than tearing the session down.
			if s.roaming.Load() {
				for s.roaming.Load() && !s.closing.Load() {
					time.Sleep(time.Millisecond)
				}
				if s.closing.Load() {
					return
				}
				continue
			}
			return
		}
	}
}

// readStream is the inbound loop for a TCP-transported SA (RFC 8229/9329): one
// frame at a time off the one stream, IKE or ESP by the non-ESP marker.
//
// There is no batching to do and none to miss. Batching on the UDP path saves
// syscalls per DATAGRAM; a stream has already coalesced whatever the network
// delivered together into one read inside the framer, so a frame loop over a
// buffered reader is the same win by a different route. The frame borrows the
// reader's buffer and is valid only until the next call — HandleInbound
// decrypts in place and writes the TUN before returning, which is the same
// contract the UDP batch above relies on.
func (s *session) readStream(pump *dataplane.Pump) {
	defer close(s.done)
	for {
		pkt, isIKE, err := s.stream.ReadFrame()
		if err != nil {
			if !s.closing.Load() {
				s.logger.Printf("ikev2: TCP stream read: %v", err)
			}
			return
		}
		if isIKE {
			// Copied out because the exchange may outlive the frame buffer.
			msg := make([]byte, len(pkt))
			copy(msg, pkt)
			s.ike.Deliver(msg)
			continue
		}
		pump.HandleInbound(pkt, nil)
	}
}

// Roam relocates the tunnel to a fresh local address after the client's network
// changed, using MOBIKE (RFC 4555): it drives an UPDATE_SA_ADDRESSES exchange
// on a new socket and swaps the ESP data path onto it, all without tearing down
// the Child SA or re-authenticating. It is a no-op error if MOBIKE was not
// negotiated with the server. Safe to call from any goroutine; calls are
// serialized.
func (s *session) Roam() error {
	if !s.ike.MobikeEnabled() {
		return fmt.Errorf("ikev2: MOBIKE was not negotiated with the server")
	}
	s.roamMu.Lock()
	defer s.roamMu.Unlock()
	if s.closing.Load() {
		return fmt.Errorf("ikev2: session closed")
	}

	// Signal the read loop that an imminent socket close is a roam, not a
	// shutdown, and suppress transient send errors on the old socket. Cleared
	// only after the new socket is published, so the read loop resumes on it.
	s.roaming.Store(true)
	defer s.roaming.Store(false)

	if err := s.ike.Roam(); err != nil {
		return fmt.Errorf("ikev2: roam: %w", err)
	}
	newConn := s.ike.DataConn()
	s.sendBC.Store(dataplane.NewBatchConn(newConn))
	s.conn.Store(newConn)
	s.logger.Printf("ikev2: MOBIKE roamed to local %s", newConn.LocalAddr())
	return nil
}

// ikeLivenessIdle is how much authenticated ESP silence must pass before a probe
// runs a DPD exchange: recent inbound ESP is itself proof the peer is alive.
const ikeLivenessIdle = 20 * time.Second

// rekeyChild runs one Child SA rekey and swaps the data path onto the fresh SA
// without dropping traffic: the new SA is installed (its inbound SPI registered
// and the outbound route repointed) before the old one is torn down, so there
// is no window where packets have no SA. It serializes with itself via rekeyMu.
func (s *session) rekeyChild() error {
	s.rekeyMu.Lock()
	defer s.rekeyMu.Unlock()
	if s.closing.Load() {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	newRes, oldInSPI, err := s.ike.RekeyChild(ctx)
	if err != nil {
		return err
	}
	newTunnel, err := newRes.BuildTunnel()
	if err != nil {
		return fmt.Errorf("build rekeyed tunnel: %w", err)
	}
	// Inherit the live peer endpoint (MOBIKE roam may have moved it).
	if u, ok := newTunnel.(interface{ SetPeerAddr(*net.UDPAddr) }); ok {
		u.SetPeerAddr(s.ike.CurrentServerAddr())
	}

	// Install the new SA first: AddTunnel registers the new inbound SPI and
	// repoints the (shared) outbound route to the new tunnel, so outbound
	// immediately uses the new keys the responder just set up. The old inbound
	// SPI stays registered until we retire it below, so ESP already in flight
	// under the old SA still decrypts.
	oldTunnel := s.tunnel
	s.pump.AddTunnel(newTunnel)
	s.tunnel = newTunnel
	s.childInSPI = newRes.InboundSPI

	// Tell the peer to delete the old SA, then retire it here. RemoveTunnel
	// unregisters by identity — both tunnels claim the same 0.0.0.0/0 route, and
	// the successor already owns it — so this drops only the old inbound SPI.
	if err := s.ike.DeleteChildSA(ctx, oldInSPI); err != nil {
		s.logger.Warnf("ikev2: delete of rekeyed-out Child SA failed: %v", err)
	}
	s.pump.RemoveTunnel(oldTunnel)
	s.logger.Printf("ikev2: Child SA rekeyed (in=%#x out=%#x)", newRes.InboundSPI, newRes.OutboundSPI)
	return nil
}

// rekeyIKE rotates the IKE SA (RFC 7296 2.18). Unlike a Child SA rekey it does
// not touch the data path: the ESP Child SAs are inherited by the new IKE SA
// unchanged, so no tunnel is swapped and no ESP packet is affected. Only the
// control-channel SPIs and keys change, inside the ike.Client. It shares
// rekeyMu with the Child rekey so the two never overlap: a Child rekey's
// install-then-delete pair completes as a unit before the IKE SA can rotate,
// and vice versa.
func (s *session) rekeyIKE() error {
	s.rekeyMu.Lock()
	defer s.rekeyMu.Unlock()
	if s.closing.Load() {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.ike.RekeyIKE(ctx); err != nil {
		return err
	}
	s.logger.Printf("ikev2: IKE SA rekeyed")
	return nil
}

// Probe implements client.Prober. Recent inbound ESP proves the peer is alive,
// so while traffic is flowing the probe does nothing. Only after a stretch of
// silence does it run one IKEv2 dead-peer-detection exchange (an empty
// INFORMATIONAL the server must answer). The client-package liveness monitor
// calls it on an interval and tears the session down after a run of failures,
// so a black-holed ESP path — the socket still "up" while nothing crosses — is
// noticed and re-dialled instead of hanging forever.
func (s *session) Probe(ctx context.Context) error {
	if s.pump.IdleFor() < ikeLivenessIdle {
		return nil
	}
	return s.ike.SendDPD(ctx)
}

// Wait blocks until the session is closed or ctx is cancelled. It returns
// ctx.Err() if the context ended first, else nil.
func (s *session) Wait(ctx context.Context) error {
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close tears down the pump, ESP socket, TUN and IKE SA. It is idempotent and
// safe to call from any goroutine.
func (s *session) Close() error {
	s.closeOnce.Do(func() {
		s.closing.Store(true)
		close(s.stopKA)
		close(s.stopRekey)
		close(s.stopIKERekey)
		if s.pump != nil {
			s.pump.Close()
		}
		if s.tun != nil {
			s.tun.Close()
		}
		// Closing the IKE client closes the shared socket, which unblocks the
		// inbound read loop.
		if s.ike != nil {
			s.closeErr = s.ike.Close()
		}
	})
	return s.closeErr
}

// connect runs the IKE handshake but returns early if ctx is cancelled,
// interrupting the in-flight Connect by closing the client's socket so the
// caller does not have to wait out Connect's read deadlines.
func connect(ctx context.Context, c *ike.Client) (*ike.ClientResult, error) {
	type outcome struct {
		res *ike.ClientResult
		err error
	}
	ch := make(chan outcome, 1)
	go func() {
		res, err := c.Connect()
		ch <- outcome{res, err}
	}()
	select {
	case <-ctx.Done():
		c.Close() // unblocks Connect's socket read
		<-ch      // let the goroutine finish so nothing leaks
		return nil, ctx.Err()
	case o := <-ch:
		return o.res, o.err
	}
}

// serverGateway resolves the server's outer IPv4 address for the host route.
// res.ServerAddr already carries the resolved server IP; fall back to parsing or
// resolving the configured host if needed.
func serverGateway(res *ike.ClientResult, host string) net.IP {
	if res.ServerAddr != nil && res.ServerAddr.IP != nil {
		return res.ServerAddr.IP
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip
	}
	if ips, err := net.LookupIP(host); err == nil {
		// Prefer an IPv4 address (the common underlay), but fall back to IPv6 so a
		// host that only resolves to AAAA still yields a host-route target.
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				return v4
			}
		}
		for _, ip := range ips {
			if ip.To16() != nil {
				return ip
			}
		}
	}
	return nil
}

// loadTLSCert loads a PEM certificate chain and private key from files.
func loadTLSCert(certFile, keyFile string) (*tls.Certificate, error) {
	c, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// loadCAPool loads a PEM CA bundle into a certificate pool.
func loadCAPool(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates found in %s", caFile)
	}
	return pool, nil
}

// parseIdentity interprets an identity string as an IP literal or an FQDN.
func parseIdentity(s string) ike.Identity {
	if ip := net.ParseIP(s); ip != nil {
		return ike.IPIdentity(ip)
	}
	return ike.FQDNIdentity(s)
}
