package nebula

// The host engine.
//
// A nebula host is a peer in a mesh rather than a client or a server: it
// listens on one UDP port, and it opens a tunnel directly to any other host it
// has traffic for. Every one of the protocols veepin implemented before this
// was hub-and-spoke, so the shape here is genuinely different — there is no
// concentrator, and the same code runs on both ends.
//
// Two lookups drive everything:
//
//   - by overlay address, to find or create a tunnel for an outbound packet
//   - by local index, to find the tunnel an inbound packet belongs to
//
// The second is why a peer can change underlay address without renegotiating:
// nothing keys off the source address, so a NAT rebinding or a roam onto
// another network is invisible above the socket.

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/xen0bit/veepin/dataplane"
)

const (
	// maxPacket bounds a datagram read. Nebula's own MTU ceiling is well under
	// this; the slack absorbs the header and AEAD tag.
	maxPacket = 9001

	// handshakeRetry is how often an unanswered handshake is resent. UDP drops
	// happen and there is no other retransmission in this protocol.
	handshakeRetry = 1 * time.Second
	// handshakeTimeout bounds how long a peer stays in handshaking state before
	// the attempt is abandoned.
	handshakeTimeout = 30 * time.Second

	// tunnelIdleTimeout is how long a tunnel survives carrying nothing. It
	// matches nebula's default, and it is what bounds a tunnel's key lifetime:
	// neither implementation rotates keys on a timer or a counter, so a tunnel
	// is re-keyed by going quiet and being rebuilt on the next packet.
	tunnelIdleTimeout = 10 * time.Minute

	// tunnelProbeIdle is how quiet a tunnel must be before it is asked whether
	// the peer is still there, and tunnelProbeGrace how long the answer may
	// take. Their sum bounds how long a silently-broken tunnel keeps being
	// selected by the routing table -- against tunnelIdleTimeout, which was
	// previously the only thing that noticed.
	//
	// The idle threshold is well below tunnelIdleTimeout so a probe always runs
	// before expiry would have dropped the tunnel anyway, and the grace is
	// generous enough that a single lost datagram on a lossy path does not
	// read as a dead peer: the next sweep re-probes rather than the first
	// silence being conclusive.
	tunnelProbeIdle  = 30 * time.Second
	tunnelProbeGrace = 15 * time.Second
)

// ErrNoRoute reports a packet for an overlay address with no known peer.
var ErrNoRoute = errors.New("nebula: no peer for that overlay address")

// errNotIPv4 reports a packet the IPv4-only overlay cannot carry.
var errNotIPv4 = errors.New("nebula: outbound packet is not IPv4")

// packetConn is the UDP socket the host owns, narrowed so tests can substitute
// an in-memory pair.
//
// The method names are net's own rather than the shorter ReadFrom/WriteTo,
// because that is what makes both *net.UDPConn and dataplane.PacketConn satisfy
// this directly. The short names forced an adapter in the facade, and that
// adapter is how nebula ended up being the one UDP server in the tree not
// replying from the address a datagram arrived on -- the wrapper was available,
// but nothing here could accept it.
type packetConn interface {
	ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error)
	WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error)
	Close() error
	LocalAddr() net.Addr
}

// Logger is the subset of logging the host uses.
// Logger is the subset of *vlog.Logger this package needs. It is an interface
// rather than the concrete type because nebula's host predates the wrapper and
// its tests substitute a recorder; Warnf is here for the same reason every other
// package has it, so a line that reports a problem survives -log-level warn.
type Logger interface {
	Printf(format string, v ...any)
	Warnf(format string, v ...any)
}

type nopLogger struct{}

func (nopLogger) Printf(string, ...any) {}
func (nopLogger) Warnf(string, ...any)  {}

// Config configures a host.
type Config struct {
	// Identity is this host's certificate and key.
	Identity *Identity
	// CAs are the trust anchors peers are verified against.
	CAs *CAPool
	// Cipher selects the AEAD; "chachapoly" or the default, "aes".
	Cipher string
	// StaticHosts maps an overlay address to the underlay addresses it can be
	// reached at, for peers that are not discovered through a lighthouse.
	StaticHosts map[netip.Addr][]netip.AddrPort
	// Lighthouses are the overlay addresses of hosts that answer queries about
	// where other hosts are.
	Lighthouses []netip.Addr
	// AmLighthouse makes this host answer such queries.
	AmLighthouse bool
	// Relays are the overlay addresses of hosts this one is willing to be
	// reached through when a direct path cannot be built. They are advertised
	// to lighthouses so a peer that cannot reach us directly knows what to
	// ask. Naming a relay does not make traffic go through it -- a direct path
	// is always tried first, and a relay is only used once the direct one has
	// demonstrably failed.
	Relays []netip.Addr
	// RelayFor makes this host willing to forward for others. It is off by
	// default and deliberately separate from Relays: agreeing to carry other
	// people's traffic is a decision about this host's bandwidth and about
	// what its operator is willing to see (a relay learns who talks to whom),
	// not something to be inferred from wanting a relay oneself.
	RelayFor bool
	// Logger receives operational messages.
	Logger Logger
	// Gate bounds how much unauthenticated work this host accepts. Nil installs
	// one with the package defaults.
	Gate *dataplane.Gate
}

func (c *Config) cipher() noiseCipher {
	if c.Cipher == "chachapoly" {
		return cipherChaChaPoly
	}
	return cipherAESGCM
}

func (c *Config) logger() Logger {
	if c.Logger == nil {
		return nopLogger{}
	}
	return c.Logger
}

// peer is everything known about one other host.
type peer struct {
	// addr is the peer's overlay address, and the key it is looked up by.
	addr netip.Addr

	mu sync.Mutex
	// underlay are the addresses this peer is reachable at, most recently
	// confirmed first.
	underlay []netip.AddrPort
	// relayVia are overlay addresses this peer says will relay for it, as
	// reported to or by a lighthouse. Claimed, never observed -- see
	// recordUpdate.
	relayVia []netip.Addr
	// tun is the established tunnel, nil until a handshake completes.
	tun *tunnel
	// pending is an in-flight handshake this host initiated.
	pending     *initiatorHandshake
	pendingMsg  []byte
	pendingAt   time.Time
	lastAttempt time.Time
}

// Host is a running nebula node.
type Host struct {
	cfg  *Config
	hs   *handshakeConfig
	conn packetConn
	tun  io.ReadWriteCloser
	log  Logger
	addr netip.Addr // this host's overlay address

	gate *dataplane.Gate

	// shaper pads outbound inner packets so the inner traffic's size pattern
	// does not survive encapsulation (dataplane/shape.go). nil disables it,
	// which is the behaviour from before it existed. shapeMTU is the largest
	// inner packet the path carries, which is what the shaper pads towards.
	//
	// Owned by the TUN reader goroutine, like every other shaper in the tree:
	// dataplane.Shaper is unlocked scratch, and sendPacket is called from that
	// one loop.
	shaper     *dataplane.Shaper
	shapeMTU   int
	shapedOnce sync.Once

	mu      sync.RWMutex
	byAddr  map[netip.Addr]*peer
	byIndex map[uint32]*tunnel
	closed  bool

	// relays carries the relay entries this host holds, in any of the three
	// roles a host can play in one. See relay.go.
	relays *relayTable

	// lighthouses are resolved at start from the configured overlay addresses.
	lighthouses []netip.Addr

	wg   sync.WaitGroup
	done chan struct{}
}

// NewHost builds a host around an already-open socket and TUN.
func NewHost(cfg *Config, conn packetConn, tun io.ReadWriteCloser) (*Host, error) {
	if cfg.Identity == nil {
		return nil, errors.New("nebula: no identity configured")
	}
	if cfg.CAs == nil {
		return nil, errors.New("nebula: no certificate authorities configured")
	}
	addr, ok := cfg.Identity.Cert.Address()
	if !ok {
		return nil, errors.New("nebula: certificate carries no overlay address")
	}

	gate := cfg.Gate
	if gate == nil {
		gate = dataplane.NewGate(dataplane.AdmissionConfig{})
	}

	h := &Host{
		cfg: cfg,
		hs: &handshakeConfig{
			cipher:   cfg.cipher(),
			identity: cfg.Identity,
			pool:     cfg.CAs,
		},
		conn:        conn,
		tun:         tun,
		log:         cfg.logger(),
		addr:        addr,
		gate:        gate,
		byAddr:      map[netip.Addr]*peer{},
		byIndex:     map[uint32]*tunnel{},
		relays:      newRelayTable(),
		lighthouses: append([]netip.Addr(nil), cfg.Lighthouses...),
		done:        make(chan struct{}),
	}

	for overlay, underlay := range cfg.StaticHosts {
		p := h.peerFor(overlay)
		p.mu.Lock()
		p.underlay = append([]netip.AddrPort(nil), underlay...)
		p.mu.Unlock()
	}
	return h, nil
}

// tunnelFor resolves an established tunnel by the index we chose for it.
func (h *Host) tunnelFor(localIndex uint32) (*tunnel, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	t, ok := h.byIndex[localIndex]
	return t, ok
}

// Addr returns this host's overlay address.
func (h *Host) Addr() netip.Addr { return h.addr }

// OverlayBits is the prefix length of the overlay network this host is on, as
// its certificate defines it.
func (h *Host) OverlayBits() int {
	if len(h.cfg.Identity.Cert.Networks) == 0 {
		return h.addr.BitLen()
	}
	return h.cfg.Identity.Cert.Networks[0].Bits()
}

// Run pumps both directions until the host is closed.
func (h *Host) Run() {
	h.wg.Add(3)
	go func() {
		defer h.wg.Done()
		h.readUDP()
	}()
	go func() {
		defer h.wg.Done()
		h.readTUN()
	}()
	go func() {
		defer h.wg.Done()
		h.maintain()
	}()
}

// maintain keeps this host's location current with its lighthouses. Without it
// a host that changes address becomes unreachable until it happens to initiate
// something itself, which in a mesh may never occur.
func (h *Host) maintain() {
	// Tunnel expiry runs whether or not lighthouses are configured: a mesh with
	// only static peers still accumulates tunnels.
	expiry := time.NewTicker(tunnelIdleTimeout / 4)
	defer expiry.Stop()
	// Reachability runs on its own, much shorter, cycle: expiry asks whether a
	// tunnel is worth keeping, this asks whether it still works.
	probe := time.NewTicker(tunnelProbeIdle / 2)
	defer probe.Stop()

	if len(h.lighthouses) == 0 {
		for {
			select {
			case <-h.done:
				return
			case <-expiry.C:
				h.expireTunnels()
			case <-probe.C:
				h.probeQuietTunnels()
			}
		}
	}
	// Report immediately so a freshly started host is reachable straight away
	// rather than after the first full interval.
	h.reportToLighthouses()

	ticker := time.NewTicker(lighthouseUpdateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-h.done:
			return
		case <-expiry.C:
			h.expireTunnels()
		case <-probe.C:
			h.probeQuietTunnels()
		case <-ticker.C:
			h.reportToLighthouses()
		}
	}
}

// expireTunnels drops tunnels that have carried nothing for a while.
//
// Nebula does the same, with a ten-minute inactivity timeout, and it is the only
// thing that bounds a tunnel's key lifetime in either implementation: neither
// rotates keys on a schedule or a counter. Its tryRehandshake re-keys only when
// the host's own certificate changes, so a continuously busy tunnel keeps one
// key until it goes quiet. Matching that behaviour is what keeps the two
// interoperable -- and without it veepin held every tunnel it ever built,
// forever, which is a leak as well as an unbounded key lifetime.
//
// A dropped tunnel costs nothing: the next packet for that peer starts a fresh
// handshake, which is exactly what happens on first contact.
func (h *Host) expireTunnels() {
	cutoff := time.Now().Add(-tunnelIdleTimeout)

	h.mu.Lock()
	var dead []*tunnel
	for idx, t := range h.byIndex {
		seen := t.LastSeen()
		if seen.IsZero() {
			seen = t.established
		}
		if seen.Before(cutoff) {
			dead = append(dead, t)
			delete(h.byIndex, idx)
		}
	}
	h.mu.Unlock()

	for _, t := range dead {
		h.releaseTunnel(t)
		h.log.Warnf("nebula: tunnel with %v idle for %v; dropped", t.PeerAddr(), tunnelIdleTimeout)
	}
}

// dropTunnel removes a tunnel from the index and releases what refers to it.
// expireTunnels does its own removal because it is already walking the map
// under the lock; this is for callers that decided a single tunnel is dead.
func (h *Host) dropTunnel(t *tunnel) {
	h.mu.Lock()
	if cur, ok := h.byIndex[t.localIndex]; ok && cur == t {
		delete(h.byIndex, t.localIndex)
	}
	h.mu.Unlock()
	h.releaseTunnel(t)
}

// releaseTunnel drops the peer's reference to a tunnel already removed from the
// index, and forgets any relay that ran over it.
func (h *Host) releaseTunnel(t *tunnel) {
	if p, ok := h.lookupPeer(t.PeerAddr()); ok {
		p.mu.Lock()
		if p.tun == t {
			p.tun = nil
		}
		p.mu.Unlock()
	}
	// Any relay this host was part of goes with it. A relay entry outlives
	// the tunnel that authenticates its hop, so keeping one means offering
	// the data path a path that cannot carry anything, and holding an
	// index the peer will have forgotten by the time it comes back.
	h.relays.forget(t.PeerAddr())
}

// Close shuts the host down and waits for its loops to finish.
func (h *Host) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	close(h.done)
	h.mu.Unlock()

	err := h.conn.Close()
	if h.tun != nil {
		// The TUN read blocks until it is closed, so both have to go.
		_ = h.tun.Close()
	}
	h.wg.Wait()
	return err
}

// peerFor returns the peer record for an overlay address, creating it if needed.
func (h *Host) peerFor(addr netip.Addr) *peer {
	h.mu.Lock()
	defer h.mu.Unlock()
	if p, ok := h.byAddr[addr]; ok {
		return p
	}
	p := &peer{addr: addr}
	h.byAddr[addr] = p
	return p
}

// lookupPeer returns an existing peer record, if any.
func (h *Host) lookupPeer(addr netip.Addr) (*peer, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	p, ok := h.byAddr[addr]
	return p, ok
}

// readTUN carries outbound packets from the TUN into tunnels.
func (h *Host) readTUN() {
	buf := make([]byte, maxPacket)
	for {
		n, err := h.tun.Read(buf)
		if err != nil {
			if !h.isClosed() {
				h.log.Printf("nebula: TUN read: %v", err)
			}
			return
		}
		if err := h.sendPacket(buf[:n]); err != nil {
			// A packet with nowhere to go is a dropped packet, not a fatal
			// condition: in a mesh it is entirely normal to have traffic for a
			// host whose tunnel has not been built yet.
			//
			// Non-IPv4 is not worth reporting at all. A version 1 overlay is
			// IPv4 only, and Linux puts IPv6 router solicitations and multicast
			// on any interface that comes up, so logging those would emit a
			// steady stream of drops that never means anything -- and would
			// bury the drops that do.
			if !errors.Is(err, errNotIPv4) {
				h.log.Warnf("nebula: dropping outbound packet: %v", err)
			}
		}
	}
}

// SetShaper installs downstream flow shaping. mtu is the inner interface MTU --
// the size the shaper pads towards. It must be called before Run; the shaper is
// read from the TUN loop without synchronisation, the same contract
// dataplane.Pump.SetShaper carries.
func (h *Host) SetShaper(s *dataplane.Shaper, mtu int) {
	h.shaper = s
	h.shapeMTU = mtu
}

// padInner grows an inner IP packet to target octets with zero filler.
//
// It only ever grows, and it never rewrites the IP header: the receiver -- ours
// or a stock nebula's -- recovers the real packet from the header's own Total
// Length, so a padded packet and an unpadded one are the same packet to
// everything above IP. Changing Total Length would make the filler part of the
// packet and corrupt whatever transport was inside it.
func padInner(pkt []byte, target int) []byte {
	if target <= len(pkt) {
		return pkt
	}
	out := make([]byte, target)
	copy(out, pkt)
	return out
}

// sendPacket routes one inner IP packet to its peer.
func (h *Host) sendPacket(pkt []byte) error {
	dst, ok := destinationAddr(pkt)
	if !ok {
		return errNotIPv4
	}

	p, ok := h.lookupPeer(dst)
	if !ok {
		// Nothing is known about this address yet. In a mesh that is the normal
		// starting state rather than an error: if the address is inside the
		// overlay, a lighthouse can say where it lives.
		//
		// The overlay check matters. Without it any stray packet -- a broadcast,
		// something misrouted -- would create a peer record, and the host map
		// would grow without bound on traffic no peer ever answers.
		if !h.inOverlay(dst) || len(h.lighthouses) == 0 {
			return fmt.Errorf("%w: %v", ErrNoRoute, dst)
		}
		p = h.peerFor(dst)
	}

	p.mu.Lock()
	t := p.tun
	p.mu.Unlock()

	if t == nil {
		// Start building the tunnel; this packet is lost, and the next one
		// through will find the tunnel up. That is how nebula behaves too.
		h.beginHandshake(p)
		return fmt.Errorf("nebula: tunnel to %v is not up yet", dst)
	}

	// Downstream flow shaping (dataplane/shape.go). The padding goes INSIDE the
	// AEAD plaintext, which is not a stylistic choice: nebula's 16-octet header
	// is passed to the AEAD as additional data, so anything appended after the
	// tag is not covered by the authentication and a conforming receiver rejects
	// the datagram rather than trimming it.
	//
	// Inside the plaintext it is inert to a stock nebula peer, by the same
	// mechanism every other shaped protocol here uses: the receiver decrypts,
	// writes the plaintext to its TUN, and the kernel's IP stack delimits the
	// real packet by the inner header's Total Length. The filler is never seen
	// by anything above IP.
	if h.shaper != nil {
		if target := h.shaper.Target(pkt, h.shapeMTU); target > len(pkt) {
			// Said out loud once, because a ping proves nothing about whether
			// shaping happened -- it passes just as happily on a silent no-op,
			// which is the failure mode this tree keeps rediscovering. The
			// shaped interop cell requires this line, so a padder that quietly
			// stopped padding fails the cell instead of passing it.
			h.shapedOnce.Do(func() {
				h.log.Printf("nebula: shaping outbound packets to %d octets (first: %d -> %d)",
					h.shapeMTU, len(pkt), target)
			})
			pkt = padInner(pkt, target)
		}
	}

	out := t.encrypt(typeMessage, subTypeNone, pkt)

	// The direct path first, always. A relay is a fallback and never a
	// preference: it costs a hop, it costs the relay's bandwidth, and it tells
	// the relay who is talking to whom.
	//
	// Any failure is enough to reach for the relay, not only "no route". A
	// blocked path -- which is the case relays exist for -- surfaces as
	// EPERM or EHOSTUNREACH from the socket rather than as an empty address
	// list, so keying the fallback on ErrNoRoute alone would leave the relay
	// unused in exactly the situation it was built for.
	directErr := h.sendToPeer(p, out)
	if directErr == nil {
		return nil
	}

	if r, ok := h.relays.terminalFor(dst); ok {
		return h.sendRelayed(r, out)
	}
	h.tryRelays(dst)
	return fmt.Errorf("nebula: %v unreachable directly (%w) and no relay is up yet", dst, directErr)
}

// tryRelays asks each configured relay to carry traffic for dst.
func (h *Host) tryRelays(dst netip.Addr) {
	for _, via := range h.cfg.Relays {
		if err := h.requestRelay(via, dst); err != nil {
			h.log.Printf("nebula: relay %v for %v: %v", via, dst, err)
		}
	}
}

// sendToPeer writes a datagram to the peer's best known underlay address.
func (h *Host) sendToPeer(p *peer, datagram []byte) error {
	p.mu.Lock()
	addrs := append([]netip.AddrPort(nil), p.underlay...)
	p.mu.Unlock()

	if len(addrs) == 0 {
		return fmt.Errorf("%w: %v has no known underlay address", ErrNoRoute, p.addr)
	}
	// Only the first candidate is used for data; the others exist so a
	// handshake can probe them.
	_, err := h.conn.WriteToUDPAddrPort(datagram, addrs[0])
	return err
}

// beginHandshake starts an exchange with a peer if one is not already running.
func (h *Host) beginHandshake(p *peer) {
	p.mu.Lock()
	if p.tun != nil {
		p.mu.Unlock()
		return
	}
	now := time.Now()
	if p.pending != nil && now.Sub(p.lastAttempt) < handshakeRetry {
		p.mu.Unlock()
		return
	}
	if p.pending != nil && now.Sub(p.pendingAt) > handshakeTimeout {
		// Give up on the old attempt and start fresh, so a handshake that was
		// answered by nothing does not wedge the peer forever.
		p.pending = nil
	}

	if p.pending == nil {
		pending, msg, err := h.hs.initiate()
		if err != nil {
			p.mu.Unlock()
			h.log.Printf("nebula: starting handshake with %v: %v", p.addr, err)
			return
		}
		p.pending = pending
		p.pendingMsg = msg
		p.pendingAt = now
	}
	p.lastAttempt = now
	msg := p.pendingMsg
	addrs := append([]netip.AddrPort(nil), p.underlay...)
	p.mu.Unlock()

	if len(addrs) == 0 {
		h.queryLighthouses(p.addr)
	}
	// Probe every candidate: with hole punching, only one may work, and which
	// one is not knowable in advance.
	direct := false
	for _, a := range addrs {
		if _, err := h.conn.WriteToUDPAddrPort(msg, a); err != nil {
			h.log.Printf("nebula: sending handshake to %v: %v", a, err)
			continue
		}
		direct = true
	}

	// And through any relay, in parallel rather than after a timeout.
	//
	// The handshake itself has to be relayable, not just the traffic that
	// follows it: the payload a relay forwards is encrypted end to end under
	// keys the two ends agree with each other, so if the exchange that agrees
	// them cannot cross, neither can anything else. Relaying only data was the
	// first shape this took and it deadlocks -- the relay is never used
	// because the tunnel it would carry never comes up.
	//
	// Both paths run every attempt. A direct path that is merely slow should
	// still win, and it does: whichever handshake response arrives first
	// completes the tunnel, and Host.install resolves the collision if both do.
	h.relayHandshake(p.addr, msg, direct)
}

// relayHandshake drives the relay half of a handshake attempt: ask each
// configured relay to carry for this peer, and send the pending stage-0
// message through any relay that has already agreed.
func (h *Host) relayHandshake(target netip.Addr, msg []byte, haveDirect bool) {
	if len(h.cfg.Relays) == 0 {
		return
	}
	for _, via := range h.cfg.Relays {
		if via == target || via == h.addr {
			continue
		}
		r, ok := h.relays.lookup(via, target)
		if !ok {
			if err := h.requestRelay(via, target); err != nil && !haveDirect {
				h.log.Printf("nebula: relay %v for %v: %v", via, target, err)
			}
			continue
		}
		if r.state != relayEstablished {
			// The request is outstanding. Re-send it rather than waiting: a
			// control message is not retransmitted by anything else, and the
			// relay has no way to know we are still interested.
			h.resendRelayRequest(via, r)
			continue
		}
		if err := h.sendRelayed(r, msg); err != nil {
			h.log.Printf("nebula: relaying handshake to %v via %v: %v", target, via, err)
			continue
		}
		h.log.Printf("nebula: sent handshake to %v via relay %v", target, via)
	}
}

// batchReader is the optional batched-read surface of the socket, which
// dataplane.PacketConn provides; the in-memory pairs tests substitute do not,
// and read one datagram at a time.
type batchReader interface {
	ReadBatch(bufs [][]byte, sizes []int, froms []*net.UDPAddr) (int, error)
}

// readUDP demultiplexes inbound datagrams — in recvmmsg batches when the socket
// supports them: one syscall drains up to readBatch datagrams under load and
// blocks like a plain read when idle.
func (h *Host) readUDP() {
	br, ok := h.conn.(batchReader)
	if !ok {
		h.readUDPSingle()
		return
	}
	const readBatch = 16
	bufs := make([][]byte, readBatch)
	for i := range bufs {
		bufs[i] = make([]byte, maxPacket)
	}
	sizes := make([]int, readBatch)
	froms := make([]*net.UDPAddr, readBatch)
	for {
		n, err := br.ReadBatch(bufs, sizes, froms)
		for i := range n {
			ap := froms[i].AddrPort()
			h.handleDatagram(bufs[i][:sizes[i]], netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
		}
		if err != nil {
			if !h.isClosed() {
				h.log.Printf("nebula: UDP read: %v", err)
			}
			return
		}
	}
}

// readUDPSingle is the one-datagram-per-read loop for sockets without a
// batched-read surface.
func (h *Host) readUDPSingle() {
	buf := make([]byte, maxPacket)
	for {
		n, from, err := h.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if !h.isClosed() {
				h.log.Printf("nebula: UDP read: %v", err)
			}
			return
		}
		h.handleDatagram(buf[:n], from)
	}
}

// handleDatagram dispatches one datagram. pkt is borrowed from the read loop's
// buffer: the data path (typeMessage) consumes it — decrypt, source check, TUN
// write — before returning, and every other type is copied out here because its
// handling may outlive the buffer.
func (h *Host) handleDatagram(pkt []byte, from netip.AddrPort) {
	hdr, err := parseHeader(pkt)
	if err != nil {
		return
	}
	if hdr.Version != headerVersion {
		return
	}

	if hdr.Type == typeMessage {
		if hdr.Subtype == subTypeRelay {
			// Demultiplexed against the relay table rather than the tunnel
			// table, on an index from a different namespace. Kept on the
			// allocation-free path with the ordinary messages it is carrying.
			h.handleRelayMessage(pkt, hdr, from)
			return
		}
		h.handleMessage(pkt, hdr, from)
		return
	}
	pkt = append([]byte(nil), pkt...)
	switch hdr.Type {
	case typeHandshake:
		h.handleHandshake(pkt, hdr, from)
	case typeLightHouse:
		h.handleLighthouse(pkt, hdr, from)
	case typeTest:
		h.handleTest(pkt, hdr, from)
	case typeControl:
		h.handleControl(pkt, hdr, from)
	case typeCloseTunnel:
		h.handleClose(pkt, hdr)
	default:
		// Unknown types are ignored rather than treated as an error: a newer
		// peer may send something this build does not implement.
	}
}

// handleHandshake completes either role of an exchange.
func (h *Host) handleHandshake(pkt []byte, hdr header, from netip.AddrPort) {
	if hdr.RemoteIndex == 0 {
		// No remote index means this is a first message and we are responding.
		//
		// Everything below -- the Noise handshake and certificate verification --
		// is asymmetric work performed for a peer that has proved nothing, which
		// is exactly what admission control exists to bound. The reservation is
		// released as soon as respond returns, since by then the work is either
		// done or abandoned; a mesh has no multi-message pending state to hold.
		if r := h.gate.Admit(net.UDPAddrFromAddrPort(from)); r != dataplane.Admitted {
			h.log.Warnf("nebula: refusing handshake from %v: %v", from, r)
			return
		}
		reply, t, err := h.hs.respond(pkt)
		h.gate.Done()
		if err != nil {
			h.log.Warnf("nebula: handshake from %v rejected: %v", from, err)
			return
		}
		// The reply retraces the path the request took. A handshake that
		// arrived through a relay must be answered through it: `from` is the
		// relay's own underlay address, and a datagram sent there plainly
		// reaches the relay as ordinary traffic addressed to nothing it holds,
		// so it is dropped and the exchange stalls with the initiator
		// retrying forever.
		if r, ok := h.relays.terminalFor(t.PeerAddr()); ok {
			if err := h.sendRelayed(r, reply); err != nil {
				h.log.Printf("nebula: relaying handshake reply to %v: %v", t.PeerAddr(), err)
				return
			}
		} else if _, err := h.conn.WriteToUDPAddrPort(reply, from); err != nil {
			h.log.Printf("nebula: replying to handshake from %v: %v", from, err)
			return
		}
		h.install(t, from)
		h.log.Printf("nebula: tunnel up with %v (%s) at %v",
			t.PeerAddr(), t.peerCert.Name, from)
		return
	}

	// Otherwise it answers a handshake this host started. The remote index the
	// peer echoed identifies which one.
	p, ok := h.peerAwaiting(hdr.RemoteIndex)
	if !ok {
		return
	}
	p.mu.Lock()
	pending := p.pending
	p.mu.Unlock()
	if pending == nil {
		return
	}

	t, err := pending.complete(pkt)
	if err != nil {
		h.log.Printf("nebula: completing handshake with %v: %v", p.addr, err)
		return
	}

	p.mu.Lock()
	p.pending = nil
	p.pendingMsg = nil
	p.mu.Unlock()

	h.install(t, from)
	h.log.Printf("nebula: tunnel up with %v (%s) at %v", t.PeerAddr(), t.peerCert.Name, from)
}

// peerAwaiting finds the peer whose in-flight handshake used a local index.
func (h *Host) peerAwaiting(localIndex uint32) (*peer, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, p := range h.byAddr {
		p.mu.Lock()
		match := p.pending != nil && p.pending.localIndex == localIndex
		p.mu.Unlock()
		if match {
			return p, true
		}
	}
	return nil, false
}

// install registers a completed tunnel under both lookups, retiring whatever
// tunnel to the same peer it replaces.
//
// Retiring the old one is not just housekeeping. A tunnel stays usable for as
// long as it is reachable through byIndex, so leaving the superseded entry there
// would keep its keys live indefinitely — a peer that rehandshakes would go on
// having its previous session accepted, and the map would grow by one entry
// every time. Handshakes recur whenever a tunnel is lost, so this accumulates on
// exactly the hosts that are having trouble.
func (h *Host) install(t *tunnel, from netip.AddrPort) {
	p := h.peerFor(t.PeerAddr())

	// Computed before p.mu is taken. isRelayUnderlay locks the relay peers it
	// consults, and when the peer being installed IS a relay -- the ordinary
	// case, since a host handshakes with its relay first -- that is the same
	// lock, and taking it twice deadlocks the goroutine that owns the
	// handshake. The symptom is not a crash: the tunnel simply never comes up
	// and nothing is logged, because the log line is on the far side of it.
	viaRelay := h.isRelayUnderlay(t.PeerAddr(), from)

	p.mu.Lock()
	old := p.tun
	keep := t
	if old != nil {
		keep = h.resolveCollision(old, t)
	}
	p.tun = keep
	// The address the handshake actually arrived from is authoritative: it is
	// where the peer can be reached right now, whatever configuration said.
	//
	// Unless it is a relay's address, which is not the peer's at all. A
	// handshake that crossed a relay arrives from the relay's socket, and
	// recording that as the peer's direct address makes every later packet a
	// plain datagram addressed to the relay -- which the socket accepts, the
	// relay receives, and the relay drops, because it holds no tunnel index
	// matching it. The tunnel reports itself up, the send succeeds, and
	// nothing arrives.
	if !viaRelay {
		p.underlay = append([]netip.AddrPort{from}, filterOut(p.underlay, from)...)
	}
	p.mu.Unlock()

	loser := t
	if keep == t {
		loser = old
	}

	h.mu.Lock()
	if loser != nil && loser != keep {
		delete(h.byIndex, loser.localIndex)
	}
	h.byIndex[keep.localIndex] = keep
	h.mu.Unlock()
}

// resolveCollision picks which of two tunnels to the same peer survives.
//
// Two hosts routinely key a tunnel to each other simultaneously here: a
// lighthouse answering a query also tells the target to punch, and the target
// starts its own handshake while the asker is starting one. Both complete, and
// each side ends up holding two.
//
// Simply keeping the newer one is not enough, because the two sides do not see
// them in the same order -- each could keep a different tunnel, and then every
// packet one sends arrives on an index the other has retired. So the winner has
// to be chosen by a rule both sides evaluate to the same answer using only what
// they both know: the tunnel initiated by the numerically lower overlay address
// wins. Whichever host is asking, that names the same tunnel.
//
// When both tunnels were initiated by the same side there is no collision to
// resolve -- it is an ordinary rehandshake -- and the newer one wins.
func (h *Host) resolveCollision(old, fresh *tunnel) *tunnel {
	if old.weInitiated == fresh.weInitiated {
		return fresh
	}
	// True when this host is the one whose initiations win.
	// True when this host is the one whose initiations win.
	oursWins := h.addr.Compare(fresh.PeerAddr()) < 0
	if fresh.weInitiated == oursWins {
		return fresh
	}
	return old
}

func filterOut(addrs []netip.AddrPort, drop netip.AddrPort) []netip.AddrPort {
	out := addrs[:0:0]
	for _, a := range addrs {
		if a != drop {
			out = append(out, a)
		}
	}
	return out
}

// handleMessage decrypts data traffic and hands it to the TUN.
func (h *Host) handleMessage(pkt []byte, hdr header, from netip.AddrPort) {
	h.mu.RLock()
	t, ok := h.byIndex[hdr.RemoteIndex]
	h.mu.RUnlock()
	if !ok {
		return
	}

	_, payload, err := t.decrypt(pkt)
	if err != nil {
		h.log.Warnf("nebula: dropping packet from %v: %v", from, err)
		return
	}

	// The peer's certificate says which source addresses it may use. Enforcing
	// it here is what stops an authenticated host from impersonating another:
	// without this, any valid member could inject traffic claiming to come from
	// any address in the mesh.
	if src, ok := sourceAddr(payload); !ok || !certAllows(t.peerCert, src) {
		h.log.Warnf("nebula: dropping packet from %v (%s): source address not permitted by its certificate",
			t.PeerAddr(), t.peerCert.Name)
		return
	}

	h.noteRoam(t, from)

	if _, err := h.tun.Write(payload); err != nil {
		// A TUN that will not take a packet is a dropped packet, not a dead
		// host: the interface may still be coming up.
		h.log.Printf("nebula: TUN write: %v", err)
	}
}

// noteRoam records a peer that has started arriving from a new address.
func (h *Host) noteRoam(t *tunnel, from netip.AddrPort) {
	p, ok := h.lookupPeer(t.PeerAddr())
	if !ok {
		return
	}
	// Same exclusion as install, and computed before the lock for the same
	// reason.
	if h.isRelayUnderlay(t.PeerAddr(), from) {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.underlay) > 0 && p.underlay[0] == from {
		return
	}
	// This only runs after the packet authenticated, so the new address is
	// attested by the tunnel's keys rather than merely claimed.
	p.underlay = append([]netip.AddrPort{from}, filterOut(p.underlay, from)...)
}

// isRelayUnderlay reports whether `from` is one of this host's relays' own
// addresses, and therefore not somewhere `peer` can be reached directly.
//
// Comparing addresses rather than threading a "this arrived via a relay" flag
// through every call site is deliberate: the flag would have to survive
// handleMessage, handleHandshake, install and noteRoam, and a path that forgot
// to carry it would reintroduce this bug somewhere with no test on it.
//
// `peer` is excluded from its own answer. A host handshakes with its relay
// like any other peer, and the relay's address is exactly where that peer is
// reachable -- refusing to record it would leave the one tunnel every other
// tunnel depends on with no address at all.
//
// **Callers must not hold any peer's lock**: this takes them.
func (h *Host) isRelayUnderlay(peer netip.Addr, from netip.AddrPort) bool {
	if len(h.cfg.Relays) == 0 || !from.IsValid() {
		return false
	}
	for _, via := range h.cfg.Relays {
		if via == peer {
			continue
		}
		p, ok := h.lookupPeer(via)
		if !ok {
			continue
		}
		p.mu.Lock()
		match := slices.Contains(p.underlay, from)
		p.mu.Unlock()
		if match {
			return true
		}
	}
	return false
}

// handleTest answers nebula's reachability probe.
func (h *Host) handleTest(pkt []byte, hdr header, _ netip.AddrPort) {
	h.mu.RLock()
	t, ok := h.byIndex[hdr.RemoteIndex]
	h.mu.RUnlock()
	if !ok {
		return
	}
	_, payload, err := t.decrypt(pkt)
	if err != nil {
		return
	}
	if hdr.Subtype != subTypeTestRequest {
		// A reply. decrypt has already moved lastSeen, which is the whole
		// answer -- the reply's payload carries no identity of its own, so
		// there is nothing to match it against and nothing more to learn from
		// it than that something authenticated arrived.
		return
	}
	p, ok := h.lookupPeer(t.PeerAddr())
	if !ok {
		return
	}
	if err := h.sendToPeer(p, t.encrypt(typeTest, subTypeTestReply, payload)); err != nil {
		h.log.Printf("nebula: replying to test from %v: %v", t.PeerAddr(), err)
	}
}

// probeQuietTunnels asks tunnels that have gone silent whether they are still
// there, and drops the ones that do not answer.
//
// This end has always replied to a peer's test packets and never sent one, so
// the mechanism could prove this host alive to others and learn nothing about
// them. Without it the only thing that noticed a tunnel had stopped working was
// expireTunnels, at tunnelIdleTimeout -- ten minutes of a peer that looks
// established, is selected by the routing table, and carries nothing.
//
// It drops the tunnel rather than reporting the session dead, which is the
// difference between a mesh and every point-to-point protocol here: one
// unreachable peer is not a dead host. A dropped tunnel costs nothing, because
// the next packet for that peer starts a fresh handshake -- exactly what
// happens on first contact.
func (h *Host) probeQuietTunnels() {
	now := time.Now()
	quiet := now.Add(-tunnelProbeIdle)

	h.mu.RLock()
	tunnels := make([]*tunnel, 0, len(h.byIndex))
	for _, t := range h.byIndex {
		tunnels = append(tunnels, t)
	}
	h.mu.RUnlock()

	var dead []*tunnel
	for _, t := range tunnels {
		seen := t.LastSeen()
		if seen.IsZero() {
			seen = t.established
		}
		if seen.After(quiet) {
			// Heard from recently: anything that authenticated answers the
			// question, so an outstanding probe is moot.
			t.clearProbe()
			continue
		}
		if t.probeExpired(now) {
			dead = append(dead, t)
			continue
		}
		if !t.awaitProbe(now.Add(tunnelProbeGrace)) {
			continue // one already in flight
		}
		p, ok := h.lookupPeer(t.PeerAddr())
		if !ok {
			continue
		}
		if err := h.sendToPeer(p, t.encrypt(typeTest, subTypeTestRequest, nil)); err != nil {
			h.log.Printf("nebula: probing %v: %v", t.PeerAddr(), err)
		}
	}
	for _, t := range dead {
		h.log.Warnf("nebula: %v did not answer a reachability probe in %v; tunnel dropped",
			t.PeerAddr(), tunnelProbeGrace)
		h.dropTunnel(t)
	}
}

// handleClose tears a tunnel down at the peer's request.
func (h *Host) handleClose(pkt []byte, hdr header) {
	h.mu.RLock()
	t, ok := h.byIndex[hdr.RemoteIndex]
	h.mu.RUnlock()
	if !ok {
		return
	}
	// Authenticate before acting: an unauthenticated close would be a trivial
	// way to knock tunnels down.
	if _, _, err := t.decrypt(pkt); err != nil {
		return
	}

	h.mu.Lock()
	delete(h.byIndex, t.localIndex)
	h.mu.Unlock()

	if p, ok := h.lookupPeer(t.PeerAddr()); ok {
		p.mu.Lock()
		if p.tun == t {
			p.tun = nil
		}
		p.mu.Unlock()
	}
	h.log.Printf("nebula: tunnel with %v closed by peer", t.PeerAddr())
}

func (h *Host) isClosed() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.closed
}

// inOverlay reports whether an address falls inside one of the networks this
// host's own certificate places it on, which is the mesh it can ask about.
func (h *Host) inOverlay(addr netip.Addr) bool {
	for _, n := range h.cfg.Identity.Cert.Networks {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

// certAllows reports whether a certificate authorizes an inner source address.
func certAllows(c *Certificate, src netip.Addr) bool {
	for _, n := range c.Networks {
		if n.Addr() == src {
			return true
		}
	}
	// A host may also route for the unsafe networks its certificate names.
	for _, n := range c.UnsafeNetworks {
		if n.Contains(src) {
			return true
		}
	}
	return false
}

// sourceAddr reads the source address of an IPv4 packet.
func sourceAddr(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(pkt[12:16])), true
}

// destinationAddr reads the destination address of an IPv4 packet.
func destinationAddr(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(pkt[16:20])), true
}
