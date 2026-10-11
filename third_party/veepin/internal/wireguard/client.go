package wireguard

// The client: one peer, one connected socket, one TUN. Dial runs the first
// handshake itself, reading the socket directly; once it returns, readLoop owns
// the socket, and rekeys and liveness probes are handed their replies through
// pendingHandshake.
//
//	Dial --handshake()--> keypair --> wgTunnel --> pump.AddTunnel
//	  |                                              |
//	  +--> readLoop:  transport --> pump.HandleInboundBatch
//	  |               response / cookie reply --> pending rekey
//	  +--> rekeyLoop: every rekeyInterval, handshakeOnce --> wgTunnel.install
//	  +--> keepalive: an empty transport message every interval

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/vlog"
	"github.com/xen0bit/veepin/internal/wireguard/noise"
	"github.com/xen0bit/veepin/internal/wireguard/transport"
	"github.com/xen0bit/veepin/internal/wireguard/wire"
)

// Handshake retransmission, from the protocol paper §6.1. An initiation is
// resent every rekeyTimeout until a response arrives or the overall attempt
// budget is spent. The initial handshake uses maxAttempts as its budget; a
// rekey, which runs against a live tunnel, retries for rekeyAttemptTime instead
// (§6.1's REKEY_ATTEMPT_TIME) so it keeps trying for nearly the whole rejection
// window before giving the tunnel up.
const (
	rekeyTimeout     = 5 * time.Second
	maxAttempts      = 5
	rekeyAttemptTime = 90 * time.Second
)

// ClientConfig is a client fully decoded and validated: keys as bytes,
// addresses as prefixes, the endpoint resolved. The public wireguard package
// builds it from options and wg-quick files; nothing here parses text.
type ClientConfig struct {
	Noise    noise.Config
	Endpoint *net.UDPAddr
	// ListenPort is the local UDP port to bind; zero lets the kernel pick.
	ListenPort int
	// AllowedIPs are the destinations routed to the peer.
	AllowedIPs []netip.Prefix
	MTU        int
	TUNName    string
	// Keepalive is the persistent-keepalive interval; zero disables it.
	Keepalive time.Duration
	// Rekey is how often the handshake is re-run.
	Rekey       time.Duration
	Obfuscation ObfuscationConfig
	// Shape is the per-flow upstream shaping budget in bytes; zero disables it.
	Shape  int
	Logger *vlog.Logger
}

// Dial performs the handshake, opens the TUN, and starts the transport data
// path. On error nothing is left running.
//
// A handshake the peer's keys refused is returned as noise.ErrDecrypt itself,
// unwrapped, for the caller to report as the authentication failure it is.
func Dial(ctx context.Context, cfg ClientConfig) (*Session, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = vlog.Discard()
	}
	conn, err := dialSocket(cfg.Endpoint, cfg.ListenPort)
	if err != nil {
		return nil, fmt.Errorf("wireguard: dial %s: %w", cfg.Endpoint, err)
	}

	jar := &cookieJar{}
	kp, err := handshake(ctx, conn, cfg.Noise, logger, cfg.Obfuscation, jar)
	if err != nil {
		conn.Close()
		if errors.Is(err, noise.ErrDecrypt) {
			return nil, err
		}
		return nil, fmt.Errorf("wireguard: handshake: %w", err)
	}

	sess, err := transport.NewSession(kp.Send, kp.Recv, kp.Local, kp.Remote)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("wireguard: transport keys: %w", err)
	}

	// GSO: the kernel may hand the pump TCP super-frames to segment and batch
	// (doc/scaling-the-data-path.md); falls back to a plain TUN transparently.
	tun, err := dataplane.OpenTUNGSO(cfg.TUNName)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("wireguard: open TUN: %w", err)
	}

	tunnel := newTunnel(sess, cfg.AllowedIPs, cfg.Endpoint, false)

	s := &Session{
		conn:          conn,
		tun:           tun,
		tunnel:        tunnel,
		logger:        logger,
		noiseCfg:      cfg.Noise,
		rekeyInterval: cfg.Rekey,
		obfCfg:        cfg.Obfuscation,
		cookies:       jar,
		done:          make(chan struct{}),
		stop:          make(chan struct{}),
	}

	// The socket is connected, so the destination is implicit and the pump's
	// PeerAddr is ignored.
	obf := cfg.Obfuscation
	send := func(pkt []byte, _ *net.UDPAddr) {
		pkt = obfuscateSend(pkt, obf)
		if _, werr := conn.Write(pkt); werr != nil {
			logger.Warnf("wireguard: send error: %v", werr)
		}
	}
	// Outbound TUN traffic is routed to the peer by longest-prefix match over its
	// AllowedIPs; inbound transport packets demux on our receiver index.
	pump := dataplane.NewPump(tun, send, wire.Demux, logger.Slog())
	if cfg.Shape > 0 {
		pump.SetShaper(dataplane.NewShaper(dataplane.ShapeConfig{Bytes: cfg.Shape}))
		logger.Printf("wireguard: outbound shaping on, %d bytes per flow", cfg.Shape)
	}
	// GSO bursts flush with one sendmmsg on the connected socket. This
	// BatchConn is the pump goroutine's own; readLoop has another.
	sendBC := dataplane.NewBatchConn(conn)
	pump.SetBatchSender(func(pkts [][]byte, _ *net.UDPAddr) {
		for i := range pkts {
			pkts[i] = obfuscateSend(pkts[i], obf)
		}
		if _, werr := sendBC.WriteBatch(pkts, nil); werr != nil {
			logger.Warnf("wireguard: batch send error: %v", werr)
		}
	})
	pump.SetInnerMTU(cfg.MTU)
	pump.AddTunnel(tunnel)
	s.pump = pump
	go pump.Run()

	go s.readLoop()
	s.startKeepalive(cfg.Keepalive)
	go s.rekeyLoop()
	return s, nil
}

// dialSocket opens the client's socket: connected, so the kernel filters to
// the endpoint and every send implicitly addresses it, and the road-warrior
// return-address handling the server side needs does not arise here.
//
// It binds listenPort when one is configured. The option was once parsed,
// validated and documented as fixing the source port for a stable NAT pinhole
// -- and then never reached this call, which bound an ephemeral port
// regardless.
func dialSocket(endpoint *net.UDPAddr, listenPort int) (*net.UDPConn, error) {
	var laddr *net.UDPAddr
	if listenPort != 0 {
		laddr = &net.UDPAddr{Port: listenPort}
	}
	return net.DialUDP("udp", laddr, endpoint)
}

// TUNName is the interface the session's data path runs on.
func (s *Session) TUNName() string { return s.tun.Name() }

// Session implements client.Session, and the two optional interfaces the
// liveness monitor discovers by type assertion. Asserted here because a
// renamed method would otherwise compile and quietly stop being found.
var (
	_ client.Session       = (*Session)(nil)
	_ client.Prober        = (*Session)(nil)
	_ client.LivenessTuner = (*Session)(nil)
)

// handshake sends the initiation and waits for the response, retransmitting a
// fresh initiation every rekeyTimeout until one is answered, the attempt budget
// is spent, or ctx is cancelled. Each attempt uses a new Initiator, since an
// initiation — and its ephemeral key — is single-use.
//
// obf, if non-zero, applies AmneziaWG wire transforms to the initiation and
// response, and emits Jc junk datagrams ahead of each initiation. jar holds the
// cookie a loaded server hands back, which every later initiation -- this
// handshake's retries and the session's rekeys -- computes mac2 with.
func handshake(ctx context.Context, conn *net.UDPConn, cfg noise.Config, logger *vlog.Logger, obf ObfuscationConfig, jar *cookieJar) (*noise.Keypair, error) {
	// The response arrives padded by S2 and a cookie reply by S3, so the buffer
	// must have room for either; sizing it to the stock 92 bytes silently
	// truncates an obfuscated response and the handshake fails with a parse
	// error that names the wrong cause.
	buf := make([]byte, max(wire.SizeHandshakeResponse+obf.PadResponse, wire.SizeCookieReply+obf.PadCookie))
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		init, err := noise.NewInitiator(cfg)
		if err != nil {
			return nil, err
		}
		jar.apply(init)
		msg, err := init.Initiation()
		if err != nil {
			return nil, err
		}
		// Junk first: the point is that the first datagram of the flow is not a
		// 148-byte initiation. Failures are ignored — junk is advisory, and a
		// peer that never sees it is no worse off.
		for _, j := range junkPackets(obf) {
			_, _ = conn.Write(j)
		}
		if _, err := conn.Write(obfuscateSend(msg, obf)); err != nil {
			return nil, fmt.Errorf("send initiation: %w", err)
		}

		deadline := time.Now().Add(rekeyTimeout)
		if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
			deadline = dl
		}
		_ = conn.SetReadDeadline(deadline)
		var n int
		cookied := false
		for {
			n, err = conn.Read(buf)
			if err != nil {
				break
			}
			recv := deobfuscateRecv(buf[:n], obf)
			if recv == nil {
				// Junk or a stray datagram: neither an error nor a response.
				// Read again against the same deadline rather than burning a
				// handshake attempt or parsing it as a response.
				continue
			}
			if t, _ := wire.Type(recv); t == wire.TypeCookieReply {
				// The server is under load and wants proof we can receive at
				// this address before it spends a Diffie-Hellman on us. One
				// that does not authenticate is read past like junk, so a
				// forged reply cannot cost an attempt.
				if cookied = takeCookie(init, recv, jar, logger); cookied {
					break
				}
				continue
			}
			n = copy(buf, recv)
			break
		}
		if cookied {
			// Retry at once with the cookie. wireguard-go waits for its
			// retransmit timer instead, but nothing in the protocol asks for
			// the wait, and it would cost every client five seconds for as
			// long as the server is busy. A reply is bound to its
			// initiation's mac1, so each initiation can prompt at most one
			// retry, and every retry counts against the attempt budget.
			if attempt >= maxAttempts {
				return nil, fmt.Errorf("server under load: no response after %d attempts", maxAttempts)
			}
			continue
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if attempt >= maxAttempts {
					return nil, fmt.Errorf("no response after %d attempts", maxAttempts)
				}
				logger.Warnf("wireguard: handshake attempt %d timed out, retrying", attempt)
				continue
			}
			return nil, err
		}

		kp, err := init.Consume(buf[:n])
		if err != nil {
			if errors.Is(err, noise.ErrDecrypt) {
				return nil, err
			}
			logger.Printf("wireguard: discarding unexpected handshake reply: %v", err)
			if attempt >= maxAttempts {
				return nil, fmt.Errorf("no valid response after %d attempts", maxAttempts)
			}
			continue
		}
		_ = conn.SetReadDeadline(time.Time{}) // clear for the steady-state loop
		return kp, nil
	}
}

// takeCookie opens a cookie reply to init's initiation and keeps the cookie,
// reporting whether it was one. A reply that does not open -- a stray, or a
// forgery -- is dropped: it must not replace a cookie that works.
func takeCookie(init *noise.Initiator, pkt []byte, jar *cookieJar, logger *vlog.Logger) bool {
	c, err := init.ConsumeCookieReply(pkt)
	if err != nil {
		logger.Printf("wireguard: discarding a cookie reply that does not authenticate: %v", err)
		return false
	}
	jar.keep(c)
	logger.Warnf("wireguard: server is under load; retrying with the cookie it sent")
	return true
}

// Session is a running WireGuard tunnel: the UDP socket, the TUN device, the
// transport pump, and the single peer tunnel whose keys it rotates. It
// implements client.Session.
type Session struct {
	conn   *net.UDPConn
	tun    *dataplane.TUN
	pump   *dataplane.Pump
	tunnel *wgTunnel
	logger *vlog.Logger

	// noiseCfg is kept so the rekey loop can start fresh handshakes, and
	// rekeyInterval is how often it does.
	noiseCfg      noise.Config
	rekeyInterval time.Duration

	// hsMu guards pending, the in-flight rekey handshake awaiting its response.
	// The initial handshake does not use it: it runs before readLoop starts, so
	// there is no dispatch to arbitrate.
	hsMu    sync.Mutex
	pending *pendingHandshake
	// hsExchMu serializes whole handshake exchanges (periodic rekey vs. a
	// liveness Probe) so only one runs at a time.
	hsExchMu sync.Mutex

	// obfCfg is the AmneziaWG obfuscation config (zero = stock WireGuard).
	obfCfg ObfuscationConfig
	// cookies is the cookie a loaded server last gave us, shared with the
	// initial handshake that created it.
	cookies *cookieJar

	closeOnce sync.Once
	closeErr  error
	done      chan struct{} // closed when the inbound loop exits
	stop      chan struct{} // stops the keepalive and rekey goroutines
}

// pendingHandshake links an in-flight rekey initiation to the goroutine awaiting
// its answer. readLoop matches an inbound response's or cookie reply's receiver
// index against localIdx and hands the packet over on ch.
type pendingHandshake struct {
	localIdx uint32
	ch       chan []byte
}

// readLoop reads datagrams off the socket and dispatches by message type:
// transport-data packets go to the pump for the tunnel, and handshake responses
// go to a waiting rekey (there is no other reason to receive one on an
// established client tunnel). Everything else — stray initiations, cookie
// replies — is dropped. It exits when the socket is closed.
func (s *Session) readLoop() {
	defer close(s.done)
	// Reads are batched (dataplane.BatchConn over the connected socket): one
	// recvmmsg drains up to readBatch datagrams under load and blocks like a
	// plain read when idle.
	const readBatch = 16
	bc := dataplane.NewBatchConn(s.conn)
	bufs := make([][]byte, readBatch)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	sizes := make([]int, readBatch)
	data := make([][]byte, 0, readBatch)
	for {
		n, err := bc.ReadBatch(bufs, sizes)
		data = data[:0]
		for i := range n {
			pkt := deobfuscateRecv(bufs[i][:sizes[i]], s.obfCfg)
			if pkt == nil {
				continue
			}
			t, ok := wire.Type(pkt)
			if !ok {
				continue
			}
			switch t {
			case wire.TypeTransportData:
				// Collected without a copy: the whole batch goes to the pump
				// at once so inbound TCP can coalesce (GRO); the pump decrypts
				// in place and writes the TUN before returning — bufs[i] is
				// not touched again until the next ReadBatch.
				data = append(data, pkt)
			case wire.TypeHandshakeResponse, wire.TypeCookieReply:
				// Copied: a delivered reply is handed to the rekey goroutine
				// and outlives this batch's buffers.
				s.deliverResponse(append([]byte(nil), pkt...))
			default:
				// A stray initiation: nothing a client acts on.
			}
		}
		if len(data) > 0 {
			s.pump.HandleInboundBatch(data, nil)
		}
		if err != nil {
			return
		}
	}
}

// deliverResponse hands a handshake response or cookie reply to the rekey
// goroutine waiting for it, matched on the receiver index it is addressed to. A
// reply for no pending handshake — a duplicate, or one that arrived after the
// waiter gave up — is dropped.
func (s *Session) deliverResponse(pkt []byte) {
	var receiver uint32
	switch len(pkt) {
	case wire.SizeHandshakeResponse:
		receiver = binary.LittleEndian.Uint32(pkt[8:12])
	case wire.SizeCookieReply:
		// A different offset: a cookie reply has no sender index before it.
		receiver = binary.LittleEndian.Uint32(pkt[4:8])
	default:
		return
	}
	s.hsMu.Lock()
	p := s.pending
	s.hsMu.Unlock()
	if p == nil || p.localIdx != receiver {
		return
	}
	// Buffered channel of one; a second response for the same index is dropped.
	select {
	case p.ch <- pkt:
	default:
	}
}

func (s *Session) setPending(p *pendingHandshake) {
	s.hsMu.Lock()
	s.pending = p
	s.hsMu.Unlock()
}

func (s *Session) clearPending() {
	s.hsMu.Lock()
	s.pending = nil
	s.hsMu.Unlock()
}

// rekeyLoop re-runs the handshake every rekeyInterval, rotating a fresh keypair
// into the tunnel so traffic never reaches the key's rejection age. It is the
// initiator half of the protocol's rekey timing (§6.1); the server responds to
// each new initiation as it would a first one.
func (s *Session) rekeyLoop() {
	if s.rekeyInterval <= 0 {
		return
	}
	tick := time.NewTicker(s.rekeyInterval)
	defer tick.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-tick.C:
			s.rekey()
		}
	}
}

// rekey runs one handshake and installs its keypair as the tunnel's current one.
// A failure leaves the existing keys in place: the next tick tries again, and
// Encapsulate refuses only once the current key passes rejectAfterTime.
func (s *Session) rekey() {
	ctx, cancel := context.WithTimeout(context.Background(), rekeyAttemptTime)
	defer cancel()
	// Abandon the attempt promptly if the session is closing.
	go func() {
		select {
		case <-s.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	if err := s.handshakeOnce(ctx); err != nil {
		s.logger.Warnf("wireguard: rekey failed: %v", err)
	}
}

// handshakeOnce runs a single handshake, installs the resulting keypair as the
// tunnel's current one, registers the new receiver index with the pump and
// retires the keypair that fell out. It is serialized (hsExchMu) so the periodic
// rekey and a liveness Probe never drive two handshakes at once — both share
// this one path, since in WireGuard a successful handshake is both the liveness
// signal and a rekey.
func (s *Session) handshakeOnce(ctx context.Context) error {
	s.hsExchMu.Lock()
	defer s.hsExchMu.Unlock()

	kp, err := s.doHandshake(ctx)
	if err != nil {
		return err
	}
	sess, err := transport.NewSession(kp.Send, kp.Recv, kp.Local, kp.Remote)
	if err != nil {
		return fmt.Errorf("transport keys: %w", err)
	}
	evicted := s.tunnel.install(sess)
	s.pump.AddInboundKey(sess.LocalIndex(), s.tunnel)
	if evicted != nil {
		s.pump.RemoveInboundKey(evicted.LocalIndex())
	}
	// Prime the new key's return path: the responder holds off sending under a
	// fresh keypair until it has received something under it.
	s.sendKeepalive(s.tunnel)
	s.logger.Printf("wireguard: rekeyed, session index %#x", sess.LocalIndex())
	return nil
}

// wgLivenessIdle is how much authenticated silence must pass before a probe
// bothers to handshake: below it, recent traffic (or the peer's keepalives) is
// itself proof of life, so the probe is free.
const wgLivenessIdle = 20 * time.Second

// Probe implements client.Prober. Recent authenticated traffic is proof enough,
// so a probe first consults the pump's idle clock and does nothing while the
// tunnel is active — which keeps it out of the way of the data path entirely.
// Only after a stretch of silence does it fall back to WireGuard's real liveness
// check: a fresh handshake the peer must answer. A dead peer never responds and
// doHandshake times out, tearing the tunnel down after the monitor's threshold;
// a live-but-idle peer answers, so the probe doubles as a rekey.
func (s *Session) Probe(ctx context.Context) error {
	if s.pump.IdleFor() < wgLivenessIdle {
		return nil
	}
	return s.handshakeOnce(ctx)
}

// LivenessConfig implements client.LivenessTuner. A WireGuard probe may run a
// full DH handshake, so it is spaced generously and given a longer per-probe
// budget (doHandshake retransmits every rekeyTimeout until answered).
func (s *Session) LivenessConfig() client.LivenessConfig {
	return client.LivenessConfig{
		Interval:    30 * time.Second,
		Timeout:     3 * rekeyTimeout,
		MaxFailures: 2,
	}
}

// doHandshake runs a rekey handshake dispatched through readLoop: it sends an
// initiation, waits for readLoop to deliver the matching response, and
// retransmits a fresh initiation every rekeyTimeout until one is answered or ctx
// (bounded by rekeyAttemptTime) is spent. Each attempt is a new Initiator, since
// an initiation and its ephemeral key are single-use.
//
// It is separate from the initial handshake, which reads the socket directly
// because readLoop is not running yet; here readLoop owns the socket, so the
// response must be handed over rather than read.
func (s *Session) doHandshake(ctx context.Context) (*noise.Keypair, error) {
	defer s.clearPending()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		init, err := noise.NewInitiator(s.noiseCfg)
		if err != nil {
			return nil, err
		}
		s.cookies.apply(init)
		msg, err := init.Initiation()
		if err != nil {
			return nil, err
		}
		ch := make(chan []byte, 1)
		s.setPending(&pendingHandshake{localIdx: init.LocalIndex(), ch: ch})
		// Obfuscated like the first initiation. Missing this is the kind of bug
		// that passes every test that only watches a tunnel come up: the
		// session establishes and then dies at the first rekey.
		if _, err := s.conn.Write(obfuscateSend(msg, s.obfCfg)); err != nil {
			return nil, fmt.Errorf("send initiation: %w", err)
		}

		kp, retry, err := s.awaitReply(ctx, init, ch)
		if err != nil {
			return nil, err
		}
		if retry {
			continue
		}
		return kp, nil
	}
}

// awaitReply waits up to rekeyTimeout for the answer to init's initiation. It
// returns the keypair; or retry, when the attempt should be repeated -- the
// timer ran out, the reply did not parse, or the server sent a cookie, in which
// case the retry goes at once and carries it, as the first handshake's does. A
// cookie reply that does not authenticate is waited past rather than retried
// on, so a forgery cannot force a fresh initiation.
func (s *Session) awaitReply(ctx context.Context, init *noise.Initiator, ch <-chan []byte) (kp *noise.Keypair, retry bool, err error) {
	timer := time.NewTimer(rekeyTimeout)
	defer timer.Stop()
	for {
		select {
		case resp := <-ch:
			if t, _ := wire.Type(resp); t == wire.TypeCookieReply {
				if takeCookie(init, resp, s.cookies, s.logger) {
					return nil, true, nil
				}
				continue
			}
			kp, err := init.Consume(resp)
			if err != nil {
				if errors.Is(err, noise.ErrDecrypt) {
					return nil, false, err
				}
				s.logger.Printf("wireguard: rekey: discarding unexpected reply: %v", err)
				return nil, true, nil
			}
			return kp, false, nil
		case <-timer.C:
			s.logger.Warnf("wireguard: rekey attempt timed out, retrying")
			return nil, true, nil
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
	}
}

// startKeepalive primes the peer's return path and, if a persistent-keepalive
// interval is configured, holds it open. WireGuard's responder will not send
// transport data on a fresh session until it has received some, so an initial
// keepalive makes the tunnel usable in both directions immediately rather than
// only after our first outbound packet.
func (s *Session) startKeepalive(interval time.Duration) {
	s.sendKeepalive(s.tunnel)
	if interval <= 0 {
		return
	}
	go func() {
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-tick.C:
				s.sendKeepalive(s.tunnel)
			}
		}
	}()
}

func (s *Session) sendKeepalive(t *wgTunnel) {
	pkt, err := t.Encapsulate(nil)
	if err != nil {
		s.logger.Printf("wireguard: keepalive: %v", err)
		return
	}
	if _, err := s.conn.Write(obfuscateSend(pkt, s.obfCfg)); err != nil {
		s.logger.Printf("wireguard: keepalive send: %v", err)
	}
}

// Wait blocks until the session is closed or ctx is cancelled.
func (s *Session) Wait(ctx context.Context) error {
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close tears down the pump, socket and TUN. It is idempotent and safe to call
// from any goroutine.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		close(s.stop)
		if s.pump != nil {
			s.pump.Close()
		}
		if s.tun != nil {
			s.tun.Close()
		}
		// Closing the socket unblocks the inbound read loop.
		if s.conn != nil {
			s.closeErr = s.conn.Close()
		}
	})
	return s.closeErr
}
