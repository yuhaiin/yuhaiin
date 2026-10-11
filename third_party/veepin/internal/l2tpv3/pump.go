package l2tpv3

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/vlog"
)

// The L2TPv3 data path.
//
//	TAP ---read frame---> encode (session ID, cookie, sublayer) ---> UDP
//	TAP <--write frame--- decode (verify cookie) <----------------- UDP
//
// This is deliberately NOT dataplane.Pump. That pump routes outbound by calling
// innerDest, which reads the first nibble of the buffer as an IP version -- on
// an Ethernet frame that nibble is the top half of the destination MAC. It
// would not fail cleanly; it would succeed by accident whenever a MAC happened
// to begin 0x4 or 0x6, which is the worst way for a data path to be wrong.
//
// dataplane.Demux, dataplane.PacketConn and dataplane.OpenTAP are reused as-is;
// only the routing decision is different, because layer 2 does not have one.

// SessionIDDemux extracts the Session ID from offset 4 of a data packet. It has
// the shape of dataplane.Demux and is used the same way dataplane.SPIDemux is.
func SessionIDDemux(pkt []byte) (uint32, bool) {
	if len(pkt) < l2tpHeaderLen {
		return 0, false
	}
	return uint32(pkt[4])<<24 | uint32(pkt[5])<<16 | uint32(pkt[6])<<8 | uint32(pkt[7]), true
}

// Sender writes one encapsulated datagram to a peer.
type Sender func(pkt []byte, to *net.UDPAddr)

// tapIO is the subset of dataplane.TUN the pump needs, so tests can supply a
// pipe instead of a device.
type tapIO interface {
	Read(buf []byte) (int, error)
	Write(pkt []byte) (int, error)
}

// Pump moves Ethernet frames between a TAP device and one or more L2TPv3
// sessions.
type Pump struct {
	tap    tapIO
	log    *vlog.Logger
	send   Sender
	shaper *dataplane.Shaper
	// frameMTU is the largest frame that fits the path, Ethernet header
	// included -- the size shaping pads up to.
	frameMTU int

	// out is the session frames read from the TAP are sent on. A static
	// pseudowire has exactly one.
	out *SessionConfig

	// peer is the address to send to. It starts as the configured peer (a
	// client dials a known address) and is updated from inbound packets, which
	// is how the server -- who has no configured peer -- learns where to reply.
	peer atomic.Pointer[net.UDPAddr]

	mu sync.RWMutex
	in map[uint32]*SessionConfig // inbound demux, keyed by OUR session ID

	// encBuf is reused across encodes. Run is the only writer, so it needs no
	// lock; this is what keeps the outbound path allocation-free.
	encBuf []byte

	lastInbound atomic.Int64
	closing     atomic.Bool
}

// NewPump creates a pump for a static L2TPv3 Ethernet pseudowire.
func NewPump(tap tapIO, send Sender, cfg *SessionConfig, logger *vlog.Logger) *Pump {
	p := &Pump{
		tap:    tap,
		log:    logger,
		send:   send,
		out:    cfg,
		in:     map[uint32]*SessionConfig{cfg.LocalSessionID: cfg},
		encBuf: make([]byte, 0, 65535),
	}
	if cfg.PeerAddr != nil {
		p.peer.Store(cfg.PeerAddr)
	}
	return p
}

// SetShaper attaches a traffic shaper to the outbound path. frameMTU is the
// largest frame the path carries, Ethernet header included.
func (p *Pump) SetShaper(s *dataplane.Shaper, frameMTU int) {
	p.shaper = s
	p.frameMTU = frameMTU
}

// Run reads Ethernet frames from the TAP, encapsulates them, and sends them to
// the peer. It returns when the TAP is closed.
func (p *Pump) Run() {
	buf := make([]byte, 65535)
	for {
		n, err := p.tap.Read(buf)
		if err != nil {
			if p.closing.Load() {
				return
			}
			p.log.Printf("l2tpv3: TAP read: %v", err)
			return
		}
		peer := p.peer.Load()
		if peer == nil {
			// A server that has not yet heard from anyone has nowhere to send.
			continue
		}
		frame := buf[:n]
		if p.shaper != nil {
			frame = padFrame(buf, n, p.shaper.TargetFrame(frame, p.frameMTU))
		}
		p.encBuf = EncodeData(p.encBuf, p.out.RemoteSessionID, p.out.RemoteCookie, p.out.Sublayer, frame)
		p.send(p.encBuf, peer)
	}
}

// padFrame extends an Ethernet frame in place to target octets. It only ever
// grows the frame, and only when the receiver can trim it again -- see
// ShapeableFrame.
func padFrame(buf []byte, n, target int) []byte {
	if target <= n || target > len(buf) || !dataplane.ShapeableFrame(buf[:n]) {
		return buf[:n]
	}
	clear(buf[n:target])
	return buf[:target]
}

// HandleInbound decodes one datagram and writes the inner Ethernet frame to the
// TAP. from is the datagram's source, which becomes the reply address.
func (p *Pump) HandleInbound(pkt []byte, from *net.UDPAddr) {
	sid, ok := SessionIDDemux(pkt)
	if !ok {
		return
	}
	p.mu.RLock()
	cfg, ok := p.in[sid]
	p.mu.RUnlock()
	if !ok {
		return
	}

	_, frame, err := DecodeData(pkt, cfg.LocalCookie, cfg.Sublayer)
	if err != nil {
		return
	}
	if len(frame) == 0 {
		return
	}

	// Only now, after the cookie verified, is the source address trustworthy
	// enough to send to. Learning it from an unverified packet would let any
	// off-path sender redirect the tunnel.
	if from != nil {
		p.peer.Store(from)
	}
	p.lastInbound.Store(time.Now().UnixNano())
	_, _ = p.tap.Write(frame)
}

// HandleInboundBatch handles one read batch.
func (p *Pump) HandleInboundBatch(pkts [][]byte, froms []*net.UDPAddr) {
	for i, pkt := range pkts {
		var from *net.UDPAddr
		if i < len(froms) {
			from = froms[i]
		}
		p.HandleInbound(pkt, from)
	}
}

// AddSession registers a session for inbound demux.
func (p *Pump) AddSession(cfg *SessionConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.in[cfg.LocalSessionID] = cfg
}

// RemoveSession unregisters a session.
func (p *Pump) RemoveSession(localSessionID uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.in, localSessionID)
}

// IdleFor reports how long since the last packet that passed the cookie check.
// A pseudowire that has never carried one reports the largest possible idle
// time rather than zero: a tunnel that never came up is not a healthy tunnel,
// and a Prober reading zero would call it one.
func (p *Pump) IdleFor() time.Duration {
	t := p.lastInbound.Load()
	if t == 0 {
		return time.Duration(1<<63 - 1)
	}
	return time.Since(time.Unix(0, t))
}

// Close stops the pump. The TAP and socket are owned by the caller, who closes
// them to unblock Run.
func (p *Pump) Close() { p.closing.Store(true) }
