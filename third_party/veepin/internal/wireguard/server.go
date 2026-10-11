package wireguard

// The server: one socket, one TUN, many peers. Its read loop is the only
// goroutine that handles handshakes, which is what lets peer state and the
// load meter go without locks of their own.
//
//	readLoop --initiation--> mac1 --> [under load: mac2, else cookie reply]
//	   |                        --> admission gate --> noise.Responder
//	   |                        --> wgTunnel (new, or rekeyed) --> pump
//	   +--transport---------> pump.HandleInboundBatch (roams on authentication)
//	pump.Run: TUN --> route by AllowedIPs --> seal --> the peer's last address

import (
	"encoding/base64"
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

// keySize is the length of a Curve25519 key.
const keySize = 32

// Peer is one client a server accepts, decoded: its static public key, the
// inner addresses it may use and is routed, and its preshared key (zero for
// none).
type Peer struct {
	PublicKey    [keySize]byte
	PresharedKey [keySize]byte
	AllowedIPs   []netip.Prefix
}

// ServerConfig is a server fully decoded and validated. The public wireguard
// package builds it from options and wg-quick files.
type ServerConfig struct {
	PrivateKey [keySize]byte
	ListenAddr *net.UDPAddr
	MTU        int
	// Shape is the per-flow downstream shaping budget in bytes; zero is off.
	Shape int
	// Gateway and Network are the server's own tunnel address and the network
	// it sits in; Gateway6 and Network6 are the IPv6 half, zero when absent.
	Gateway  net.IP
	Network  *net.IPNet
	Gateway6 netip.Addr
	Network6 netip.Prefix
	Peers    []Peer
	TUNName  string
	// Obfuscation is AmneziaWG's wire transform; zero is stock WireGuard.
	Obfuscation ObfuscationConfig
	// CookieThreshold is the initiation rate beyond which the server is under
	// load; zero means DefaultCookieThreshold and negative means always.
	CookieThreshold int
	Logger          *vlog.Logger
}

// serverPeer is a configured client plus its live session state. Only the
// server's single read loop mutates lastTS and tunnel, so they need no lock of
// their own.
type serverPeer struct {
	pubKey     [keySize]byte
	psk        [keySize]byte
	allowedIPs []netip.Prefix

	lastTS [wire.TimestampLen]byte // newest handshake timestamp, for replay rejection
	tunnel *wgTunnel               // current session, nil until the first handshake
}

// Server is a running WireGuard responder: a UDP socket, a TUN device, the
// transport pump, and the set of peers it accepts. It owns the TUN but does not
// configure host networking — Gateway and Network report what a caller needs to
// do that itself.
type Server struct {
	localStatic [keySize]byte
	listenAddr  *net.UDPAddr
	mtu         int
	shape       int // per-flow downstream shaping budget; 0 disables it
	gateway     net.IP
	network     *net.IPNet
	// gateway6/network6 are the IPv6 half, zero when Address6 was empty. They
	// are netip because that is what client.DualStackServer takes, and
	// netip.Prefix has a zero value a caller can test where a nil *net.IPNet
	// reads as an absent field and a bug equally well.
	gateway6 netip.Addr
	network6 netip.Prefix
	obfCfg   ObfuscationConfig // AmneziaWG wire obfuscation (zero = stock)

	logger *vlog.Logger
	tun    *dataplane.TUN
	// gate bounds unauthenticated handshake work; see internal admission notes.
	gate *dataplane.Gate
	// cookies and load are the protocol's own defence against a flood, which
	// the gate is the floor under: see cookie.go.
	cookies *noise.CookieChecker
	load    handshakeLoad

	mu    sync.Mutex
	peers map[[keySize]byte]*serverPeer

	conn *dataplane.PacketConn
	pump *dataplane.Pump

	closeOnce sync.Once
	closeErr  error
	closed    chan struct{}
}

// NewServer builds a server from cfg and opens the TUN device. It does not bind
// the socket until ListenAndServe. Opening a TUN device requires CAP_NET_ADMIN.
func NewServer(cfg ServerConfig) (*Server, error) {
	if len(cfg.Peers) == 0 {
		return nil, errors.New("wireguard: a server needs at least one peer")
	}
	peers := make(map[[keySize]byte]*serverPeer, len(cfg.Peers))
	for i, p := range cfg.Peers {
		if _, dup := peers[p.PublicKey]; dup {
			return nil, fmt.Errorf("wireguard: peer %d: duplicate public key", i)
		}
		peers[p.PublicKey] = &serverPeer{pubKey: p.PublicKey, psk: p.PresharedKey, allowedIPs: p.AllowedIPs}
	}

	cookies, err := noise.NewCookieChecker(cfg.PrivateKey, cfg.Obfuscation.TypeInitiation)
	if err != nil {
		return nil, fmt.Errorf("wireguard: %w", err)
	}
	threshold := cfg.CookieThreshold
	if threshold == 0 {
		threshold = DefaultCookieThreshold
	}
	logger := cfg.Logger
	if logger == nil {
		logger = vlog.Discard()
	}

	// GSO: the kernel may hand the pump TCP super-frames to segment and batch
	// (doc/scaling-the-data-path.md); falls back to a plain TUN transparently.
	tun, err := dataplane.OpenTUNGSO(cfg.TUNName)
	if err != nil {
		return nil, fmt.Errorf("wireguard: open TUN: %w", err)
	}

	return &Server{
		cookies:     cookies,
		load:        handshakeLoad{threshold: threshold, now: time.Now},
		localStatic: cfg.PrivateKey,
		listenAddr:  cfg.ListenAddr,
		obfCfg:      cfg.Obfuscation,
		mtu:         cfg.MTU,
		shape:       cfg.Shape,
		gateway:     cfg.Gateway,
		network:     cfg.Network,
		gateway6:    cfg.Gateway6,
		network6:    cfg.Network6,
		logger:      logger,
		tun:         tun,
		gate:        dataplane.NewGate(dataplane.AdmissionConfig{}),
		peers:       peers,
		closed:      make(chan struct{}),
	}, nil
}

// TUNName is the interface the data path is bound to.
func (s *Server) TUNName() string { return s.tun.Name() }

// Gateway is the server's own tunnel-side address.
func (s *Server) Gateway() net.IP { return s.gateway }

// Network is the tunnel subnet, for routing and NAT rules.
func (s *Server) Network() *net.IPNet { return s.network }

// Gateway6 is the server's own tunnel-side IPv6 address, or the zero Addr when
// the server was configured without one.
//
// It and Network6 implement client.DualStackServer, which is what carries the
// v6 half through to internal/hostnet: the interface address, forwarding, and
// the ip6tables MASQUERADE and FORWARD rules.
//
// Until this existed, `veepin serve wireguard` could carry inner IPv6 and could
// not be *reached* over it. Cryptokey routing admitted v6 (that was fixed with
// its own cell), AllowedIPs parsed and stored v6 prefixes, and the data path
// moved v6 packets — but the server's own address never reached the interface,
// so the interop cell had to add it by hand from the entrypoint script with a
// comment saying why. That comment was the accurate description of a gap, and
// this is the gap closed.
func (s *Server) Gateway6() netip.Addr { return s.gateway6 }

// Network6 is the tunnel's IPv6 subnet, for routing and NAT rules. See
// Gateway6.
func (s *Server) Network6() netip.Prefix { return s.network6 }

// Server implements client.DualStackServer, which is how cmd/veepin and the
// supervisor find the v6 half without client.Server having to carry a pair of
// methods every IPv4-only facade would answer nothing to. Asserted here so
// renaming either method is a compile error rather than a listener that
// silently stops configuring v6.
var _ client.DualStackServer = (*Server)(nil)

// MTU is the recommended inner-interface MTU.
func (s *Server) MTU() int { return s.mtu }

// ListenAndServe binds the UDP socket, starts the data path, and serves
// handshakes and transport traffic until Close. It blocks.
func (s *Server) ListenAndServe() error {
	conn, err := net.ListenUDP("udp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("wireguard: listen %s: %w", s.listenAddr, err)
	}
	s.conn = dataplane.NewPacketConn(conn)

	// Unconnected socket: each send addresses a specific peer, so the pump's send
	// uses the tunnel's current PeerAddr.
	send := func(pkt []byte, to *net.UDPAddr) {
		if to == nil {
			return
		}
		pkt = obfuscateSend(pkt, s.obfCfg)
		if _, werr := conn.WriteToUDP(pkt, to); werr != nil {
			s.logger.Printf("wireguard: send to %s: %v", to, werr)
		}
	}
	s.pump = dataplane.NewPump(s.tun, send, wire.Demux, s.logger.Slog())
	// GSO bursts flush with one sendmmsg, source-pinned like every send.
	s.pump.SetBatchSender(func(pkts [][]byte, to *net.UDPAddr) {
		if to == nil {
			return
		}
		for i := range pkts {
			pkts[i] = obfuscateSend(pkts[i], s.obfCfg)
		}
		if _, werr := s.conn.WriteBatch(pkts, to); werr != nil {
			s.logger.Printf("wireguard: batch send to %s: %v", to, werr)
		}
	})
	if s.shape > 0 {
		s.pump.SetShaper(dataplane.NewShaper(dataplane.ShapeConfig{Bytes: s.shape}))
		s.logger.Printf("wireguard: downstream shaping on, %d bytes per flow", s.shape)
	}
	// Oversized inner packets are answered with ICMP rather than dropped, so a
	// client learns the tunnel MTU instead of black-holing.
	s.pump.SetInnerMTU(s.mtu)
	go s.pump.Run()

	s.logger.Printf("wireguard: serving on %s, gateway %s, %d peer(s)",
		conn.LocalAddr(), s.gateway, len(s.peers))
	if s.load.threshold < 0 {
		// Said once, here, because a permanently loaded server never changes
		// state and so never logs one -- and the operator should be able to
		// see why every client takes an extra round trip.
		s.logger.Printf("wireguard: cookies required on every initiation (-cookie-threshold -1)")
	}
	s.readLoop()
	return nil
}

// readLoop dispatches inbound datagrams: initiations to the handshake, transport
// data to the pump, everything else dropped. It runs until the socket closes.
// Reads are batched (dataplane.PacketConn.ReadBatch): one recvmmsg drains up to
// readBatch datagrams under load and blocks like a plain read when idle, so
// batching adds no latency to a quiet tunnel.
func (s *Server) readLoop() {
	const readBatch = 16
	bufs := make([][]byte, readBatch)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	sizes := make([]int, readBatch)
	froms := make([]*net.UDPAddr, readBatch)
	data := make([][]byte, 0, readBatch)
	dataFroms := make([]*net.UDPAddr, 0, readBatch)
	for {
		n, err := s.conn.ReadBatch(bufs, sizes, froms)
		data, dataFroms = data[:0], dataFroms[:0]
		for i := range n {
			pkt, from := bufs[i][:sizes[i]], froms[i]
			pkt = deobfuscateRecv(pkt, s.obfCfg)
			if pkt == nil {
				continue
			}
			typ, ok := wire.Type(pkt)
			if !ok {
				continue
			}
			switch typ {
			case wire.TypeHandshakeInitiation:
				// Copied out: handshake handling should not be trusted with a
				// buffer the next batch will overwrite.
				s.handleInitiation(append([]byte(nil), pkt...), from)
			case wire.TypeTransportData:
				// Collected without a copy: the whole batch goes to the pump
				// at once so inbound TCP can coalesce (GRO); the pump decrypts
				// in place, updates each peer's return address from its source
				// (so a roaming client's replies follow it), and writes the
				// TUN before returning — bufs[i] is not touched again until
				// the next ReadBatch.
				data = append(data, pkt)
				dataFroms = append(dataFroms, from)
			default:
				// Handshake responses and cookie replies are the initiator's to send,
				// not to receive; drop them.
			}
		}
		if len(data) > 0 {
			s.pump.HandleInboundBatch(data, dataFroms)
		}
		if err != nil {
			return // socket closed on Close
		}
	}
}

// handleInitiation runs the responder handshake for one initiation and, on
// success, installs the peer's transport session in the pump.
func (s *Server) handleInitiation(pkt []byte, from *net.UDPAddr) {
	// A handshake initiation costs the responder two DH operations and the
	// keypair state that follows, all for a peer that has proved nothing at an
	// address that is spoofable. Three gates, cheapest first.
	//
	// mac1 proves the sender knows our public key. It is a keyed hash, so a
	// packet not aimed at us is refused for almost nothing -- common noise on
	// an open port, not worth logging.
	if !s.cookies.CheckMAC1(pkt) {
		return
	}
	// Under load, mac2 proves the sender can receive at the address it sent
	// from: it is computed with a cookie we only ever send to that address.
	// Without it the answer is a cookie reply -- one hash and one AEAD seal,
	// no Diffie-Hellman and no state -- and a spoofed-source flood, which
	// never sees those replies, never gets past here.
	if s.underLoad() && !s.cookies.CheckMAC2(pkt, from.AddrPort()) {
		s.sendCookieReply(pkt, from)
		return
	}
	// Then admission control, the floor under every protocol here. Under load
	// its per-source limit is finally meaningful: the source has been proved.
	//
	// The reservation covers only the initiation: by the time this returns the
	// work is done and the session, if any, is authenticated.
	if r := s.gate.Admit(from); r != dataplane.Admitted {
		s.logger.Warnf("wireguard: refusing initiation from %s: %v", from, r)
		return
	}
	defer s.gate.Done()

	r, err := noise.NewResponderWithTypes(s.localStatic, s.obfCfg.TypeInitiation, s.obfCfg.TypeResponse)
	if err != nil {
		s.logger.Printf("wireguard: responder: %v", err)
		return
	}
	peerStatic, ts, err := r.Consume(pkt)
	if err != nil {
		// ErrMAC1 means the packet was not addressed to us — common noise on an
		// open port, not worth logging loudly.
		if !errors.Is(err, noise.ErrMAC1) {
			s.logger.Warnf("wireguard: rejecting initiation from %s: %v", from, err)
		}
		return
	}

	s.mu.Lock()
	peer := s.peers[peerStatic]
	if peer == nil {
		s.mu.Unlock()
		s.logger.Printf("wireguard: initiation from unknown peer %s (%s)", shortKey(peerStatic), from)
		return
	}
	// Reject a replayed or stale initiation: its timestamp must advance.
	if peer.lastTS != ([wire.TimestampLen]byte{}) && !wire.After(ts, peer.lastTS) {
		s.mu.Unlock()
		s.logger.Printf("wireguard: replayed initiation from %s", shortKey(peerStatic))
		return
	}

	respPkt, kp, err := r.Response(peer.psk)
	if err != nil {
		s.mu.Unlock()
		s.logger.Printf("wireguard: building response for %s: %v", shortKey(peerStatic), err)
		return
	}
	sess, err := transport.NewSession(kp.Send, kp.Recv, kp.Local, kp.Remote)
	if err != nil {
		s.mu.Unlock()
		s.logger.Printf("wireguard: transport keys for %s: %v", shortKey(peerStatic), err)
		return
	}
	peer.lastTS = ts
	var evicted *transport.Session
	firstHandshake := peer.tunnel == nil
	if firstHandshake {
		peer.tunnel = newTunnel(sess, peer.allowedIPs, from, true)
	} else {
		// A re-handshake (the client's rekey): rotate the new keypair in as
		// current, keeping the old one live as previous so in-flight packets under
		// it still decrypt, and follow the source in case the client roamed.
		peer.tunnel.SetPeerAddr(from)
		evicted = peer.tunnel.install(sess)
	}
	tunnel := peer.tunnel
	s.mu.Unlock()

	// Register the new session's receiver index with the pump and retire the one
	// that fell out. The first handshake also installs the peer's routes; a rekey
	// reuses the same tunnel, so its routes are already in place. The read loop is
	// single-threaded, so no concurrent initiation races this.
	if firstHandshake {
		s.pump.AddTunnel(tunnel)
	} else {
		s.pump.AddInboundKey(sess.LocalIndex(), tunnel)
		if evicted != nil {
			s.pump.RemoveInboundKey(evicted.LocalIndex())
		}
	}

	// Obfuscated like every other outbound message. This is not on the pump's
	// send path, so it does not inherit the transform applied there — and a
	// stock-shaped response to an obfuscated initiation is dropped by the peer
	// as unparseable, which looks exactly like the server never answering.
	if _, err := s.conn.WriteToUDP(obfuscateSend(respPkt, s.obfCfg), from); err != nil {
		s.logger.Printf("wireguard: send response to %s: %v", from, err)
		return
	}
	s.logger.Printf("wireguard: handshake complete with %s at %s", shortKey(peerStatic), from)
}

// underLoad counts one initiation that passed mac1 and reports whether the
// server is under load, saying so once each time that changes.
func (s *Server) underLoad() bool {
	loaded, changed := s.load.observe()
	if changed {
		if loaded {
			s.logger.Warnf("wireguard: under load (more than %d initiations a second); answering initiations without a valid cookie with a cookie reply", s.load.threshold)
		} else {
			s.logger.Printf("wireguard: no longer under load")
		}
	}
	return loaded
}

// sendCookieReply answers an initiation that lacked a valid mac2 while the
// server is under load. It does not log per reply: under a flood that would
// be one line per spoofed datagram, which is a second flood.
func (s *Server) sendCookieReply(init []byte, to *net.UDPAddr) {
	reply, err := s.cookies.CookieReply(init, to.AddrPort())
	if err != nil {
		s.logger.Printf("wireguard: building a cookie reply: %v", err)
		return
	}
	_, _ = s.conn.WriteToUDP(obfuscateSend(reply, s.obfCfg), to)
}

// Close stops the data path and releases the socket and TUN device. It is
// idempotent.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		if s.pump != nil {
			s.pump.Close()
		}
		if s.conn != nil {
			s.closeErr = s.conn.Close() // unblocks readLoop
		}
		s.tun.Close()
		close(s.closed)
	})
	return s.closeErr
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

// Peers returns every configured peer with their live state, implementing
// client.PeerDescriber so the management panel shows a peer list for WireGuard
// and AmneziaWG (which reuses this Server type). An unknown peer — one that
// has never completed a handshake — reports State "disconnected" with an empty
// LastHandshake. A connected peer's last-handshake time is the wall-clock time
// at which the current tunnel session was installed (rekeyed sessions update
// it). The public key is short-prefix-abbreviated for the panel; the full key
// is always available in the listener config file.
func (s *Server) Peers() []client.PeerInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]client.PeerInfo, 0, len(s.peers))
	for _, p := range s.peers {
		pk := base64.StdEncoding.EncodeToString(p.pubKey[:])
		addr := ""
		if len(p.allowedIPs) > 0 {
			addr = p.allowedIPs[0].String()
		}
		info := client.PeerInfo{
			ID:      pk,
			Address: addr,
			State:   "disconnected",
		}
		if t := p.tunnel; t != nil {
			t.mu.RLock()
			if !t.established.IsZero() {
				info.State = "connected"
				info.LastHandshake = t.established.UTC().Format(time.RFC3339)
			}
			t.mu.RUnlock()
			if st, ok := s.pump.TunnelStats(t); ok {
				info = info.WithTraffic(st.RxPackets, st.RxBytes, st.TxPackets, st.TxBytes, st.LastSeen, true)
			}
		}
		out = append(out, info)
	}
	return out
}

// shortKey is a base64 key abbreviated for logs — enough to tell peers apart
// without filling a line.
func shortKey(k [keySize]byte) string {
	s := base64.StdEncoding.EncodeToString(k[:])
	return s[:8] + "…"
}
