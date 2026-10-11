package openvpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/openvpn/control"
	"github.com/xen0bit/veepin/internal/openvpn/data"
	"github.com/xen0bit/veepin/internal/openvpn/wire"
	"github.com/xen0bit/veepin/internal/vlog"
)

// muxer owns the single UDP socket and splits inbound datagrams by opcode:
// control packets go to the TLS control channel, data packets to the pump once
// the data path is up. Keeping one reader on the socket lets both channels share
// it.
type muxer struct {
	conn    *net.UDPConn
	control *control.Channel
	logger  *vlog.Logger

	mu   sync.Mutex
	pump *dataplane.Pump // nil until the data path is established

	closeOnce sync.Once
	closed    chan struct{}
}

func (m *muxer) setPump(p *dataplane.Pump) {
	m.mu.Lock()
	m.pump = p
	m.mu.Unlock()
}

// readLoop reads datagrams until the socket closes, dispatching each by opcode.
// Reads are batched (dataplane.BatchConn over the connected socket): one
// recvmmsg drains up to readBatch datagrams under load and blocks like a plain
// read when idle.
func (m *muxer) readLoop() {
	const readBatch = 16
	bc := dataplane.NewBatchConn(m.conn)
	bufs := make([][]byte, readBatch)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	sizes := make([]int, readBatch)
	dataPkts := make([][]byte, 0, readBatch)
	for {
		n, err := bc.ReadBatch(bufs, sizes)
		dataPkts = dataPkts[:0]
		for i := range n {
			pkt := bufs[i][:sizes[i]]
			op, _, ok := wire.Opcode(pkt)
			if !ok {
				continue
			}
			switch {
			case data.IsDataOpcode(op):
				// Collected without a copy: the whole batch goes to the pump
				// at once so inbound TCP can coalesce (GRO); the pump decrypts
				// in place and writes the TUN before returning — bufs[i] is
				// not touched again until the next ReadBatch. The socket
				// source is implicit on a connected client socket.
				dataPkts = append(dataPkts, pkt)
			case wire.IsControl(op):
				m.control.Deliver(pkt) // copies internally
			}
		}
		if len(dataPkts) > 0 {
			m.mu.Lock()
			pump := m.pump
			m.mu.Unlock()
			if pump != nil {
				pump.HandleInboundBatch(dataPkts, nil)
			}
		}
		if err != nil {
			return
		}
	}
}

func (m *muxer) Close() {
	m.closeOnce.Do(func() {
		close(m.closed)
		if m.control != nil {
			m.control.Close()
		}
		m.conn.Close() // unblocks readLoop
	})
}

// errNotIP reports a decrypted data packet that is not a well-formed IP packet.
// The data channel carries only IP and keepalive pings, so anything else is a
// broken or hostile peer rather than something to hand the TUN.
var errNotIP = errors.New("openvpn: data packet is not a well-formed IP packet")

// dataCipher is the data-channel crypto the tunnel drives: either the AES-256-GCM
// Cipher or the AES-256-CBC CBCCipher, chosen by the negotiated cipher.
type dataCipher interface {
	Seal(plaintext []byte) ([]byte, error)
	// SealPadded is Seal with the plaintext extended to minInner octets, the
	// vehicle downstream flow shaping uses (dataplane/shape.go).
	SealPadded(plaintext []byte, minInner int) ([]byte, error)
	Open(pkt []byte) ([]byte, error)
}

// tunnel is the data-path view of the server connection. It implements
// dataplane.Tunnel: everything from the TUN is sealed to the one server, and
// inbound data packets are opened and (if a keepalive ping) dropped.
type tunnel struct {
	cipher dataCipher
	routes []netip.Prefix
	peer   atomic.Pointer[net.UDPAddr]
}

func (t *tunnel) InboundKey() uint32                   { return dataTunnelKey }
func (t *tunnel) Routes() []netip.Prefix               { return t.routes }
func (t *tunnel) PeerAddr() *net.UDPAddr               { return t.peer.Load() }
func (t *tunnel) Encapsulate(p []byte) ([]byte, error) { return t.cipher.Seal(p) }

// EncapsulatePadded implements dataplane.PaddingTunnel. The data channel
// length-delimits its payload, so filler past the inner IP packet is delimited
// by that packet's own header and is inert to any conforming receiver.
func (t *tunnel) EncapsulatePadded(p []byte, minInner int) ([]byte, error) {
	return t.cipher.SealPadded(p, minInner)
}

func (t *tunnel) Decapsulate(pkt []byte) ([]byte, error) {
	pt, err := t.cipher.Open(pkt)
	if err != nil {
		return nil, err
	}
	if data.IsPing(pt) {
		return nil, nil // keepalive: authenticated but nothing to deliver
	}
	// Trim any shaping filler past the inner packet; the data channel delimits
	// its payload by length, so only the IP header says where the packet ends.
	inner := dataplane.TrimToIP(pt)
	if inner == nil {
		return nil, errNotIP
	}
	return inner, nil
}

// session is a running OpenVPN tunnel. It implements client.Session.
type session struct {
	muxer  *muxer
	tun    *dataplane.TUN
	pump   *dataplane.Pump
	tunnel *tunnel
	conn   *net.UDPConn
	logger *vlog.Logger

	// deadline is how long inbound silence may last before Probe calls the peer
	// gone, derived from what the server promised in its PUSH_REPLY. Zero means
	// it promised nothing and this session implements no liveness claim.
	deadline time.Duration

	closeOnce sync.Once
	closeErr  error
	done      chan struct{}
}

// errPeerSilent is the probe's verdict. It is a value rather than a formatted
// error so the reason can be attached without the liveness monitor's repeated
// failures each allocating one.
var errPeerSilent = errors.New("openvpn: the server stopped sending the keepalives it promised")

// livenessDeadline turns the server's PUSH_REPLY into the silence this client
// will tolerate.
//
// `ping-restart N` is OpenVPN's own name for exactly this question -- "restart
// if nothing has been received for N seconds" -- so where the server pushes it,
// that is the answer and nothing here needs to invent one. Where it pushes only
// `ping N`, the deadline is a small multiple of it: OpenVPN's own stock pairing
// is `keepalive 10 60`, a factor of six, and matching that keeps a client from
// declaring death sooner than the server that configured it expects.
//
// Where the server pushed neither, this returns zero and Probe makes no claim.
// That is the honest answer and not a gap to be filled with a guess: a server
// run without `keepalive` sends nothing on an idle tunnel, so silence there is
// the normal state and a timeout on it would tear down healthy sessions.
func livenessDeadline(p *pushConfig) time.Duration {
	if p.pingRestart > 0 {
		return p.pingRestart
	}
	if p.ping > 0 {
		return 6 * p.ping
	}
	return 0
}

// Probe implements client.Prober.
//
// OpenVPN over UDP is named in client/liveness.go as a protocol that can
// black-hole silently -- the socket stays up while nothing crosses -- and it is
// the one there with no request/response liveness of any kind. Its ping is
// fire-and-forget and is never echoed, so the only signal available is that
// nothing has arrived, and that signal only means something if the server said
// it would be sending something.
//
// So this consults the pump's idle clock rather than putting a packet on the
// wire. The session's own keepalive goroutine is what holds the NAT binding
// open; adding a second outbound ping here would hold it open just as well and
// still learn nothing, because nothing answers either one.
func (s *session) Probe(context.Context) error {
	if s.deadline <= 0 {
		return nil
	}
	idle := s.pump.IdleFor()
	if idle < s.deadline {
		return nil
	}
	return fmt.Errorf("%w: silent for %v, deadline %v", errPeerSilent, idle.Round(time.Second), s.deadline)
}

// LivenessConfig implements client.LivenessTuner. The deadline is already the
// whole judgement -- Probe compares one clock against it and returns -- so a
// single failure is conclusive and there is nothing for MaxFailures to tolerate
// that the deadline has not tolerated already. The default four failures at
// fifteen seconds would silently add another minute to every ping-restart the
// server pushed.
func (s *session) LivenessConfig() client.LivenessConfig {
	if s.deadline <= 0 {
		// No claim to check, so nothing to check it on: take the package
		// default rather than spinning a timer against a probe that has
		// already decided to return nil.
		return client.LivenessConfig{}
	}
	interval := max(s.deadline/4, time.Second)
	return client.LivenessConfig{
		Interval:    interval,
		Timeout:     time.Second, // Probe reads a clock; it cannot block.
		MaxFailures: 1,
	}
}

// keepalive sends a data-channel ping now and on an interval, so the server (and
// any NAT on the path) keeps the session alive even when the TUN is idle.
func (s *session) keepalive() {
	s.sendPing()
	tick := time.NewTicker(keepaliveInterval)
	defer tick.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-tick.C:
			s.sendPing()
		}
	}
}

func (s *session) sendPing() {
	pkt, err := s.tunnel.Encapsulate(data.Ping)
	if err != nil {
		s.logger.Printf("openvpn: keepalive: %v", err)
		return
	}
	if _, err := s.conn.Write(pkt); err != nil {
		s.logger.Printf("openvpn: keepalive send: %v", err)
	}
}

// Wait blocks until the session is closed or ctx is cancelled.
func (s *session) Wait(ctx context.Context) error {
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close tears down the data path, control channel, socket and TUN. It is
// idempotent.
func (s *session) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		if s.pump != nil {
			s.pump.Close()
		}
		if s.tun != nil {
			s.tun.Close()
		}
		s.muxer.Close()
	})
	return s.closeErr
}

// pushConfig is the subset of a PUSH_REPLY this client applies.
type pushConfig struct {
	localIP net.IP
	netmask net.IP
	gateway net.IP
	// localIP6 and prefix6 come from a pushed ifconfig-ipv6. They are the zero
	// values on an IPv4-only tunnel, which is every server that does not push
	// the option.
	localIP6 net.IP
	prefix6  int
	peerID   uint32
	mtu      int
	cipher   string // the data cipher the server negotiated, if it pushed one
	// ping is how often the server said it will send a keepalive, and
	// pingRestart how long it said a peer should wait before giving up. Both
	// are zero when the server pushed neither, which is the case in which this
	// client can make no liveness claim at all -- see (*session).Probe.
	ping        time.Duration
	pingRestart time.Duration
}

// parsePush decodes a server PUSH_REPLY, extracting the tunnel address, gateway,
// peer-id and MTU. An AUTH_FAILED reply is mapped to an auth error.
func parsePush(reply string) (*pushConfig, error) {
	if strings.HasPrefix(reply, "AUTH_FAILED") {
		return nil, fmt.Errorf("%w: %s", client.ErrAuth, reply)
	}
	if !strings.HasPrefix(reply, "PUSH_REPLY") {
		return nil, fmt.Errorf("unexpected server reply: %q", reply)
	}
	p := &pushConfig{mtu: defaultMTU}
	for opt := range strings.SplitSeq(reply, ",") {
		fields := strings.Fields(opt)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "ifconfig":
			if len(fields) >= 2 {
				p.localIP = net.ParseIP(fields[1])
			}
			if len(fields) >= 3 {
				second := net.ParseIP(fields[2])
				if isNetmask(second) {
					p.netmask = second
				} else {
					p.gateway = second
					p.netmask = net.IPv4(255, 255, 255, 255)
				}
			}
		case "ifconfig-ipv6":
			// `ifconfig-ipv6 <local>/<bits> <remote>`. The local half is ours;
			// the remote half is the server's own address, which the caller
			// does not need -- the connected route the prefix creates already
			// reaches it, exactly as the v4 half works.
			if len(fields) >= 2 {
				addr, bits, found := strings.Cut(fields[1], "/")
				ip := net.ParseIP(addr)
				if ip == nil || ip.To4() != nil {
					return nil, fmt.Errorf("server pushed a bad ifconfig-ipv6 address %q", fields[1])
				}
				n := 64
				if found {
					var err error
					if n, err = strconv.Atoi(bits); err != nil || n < 0 || n > 128 {
						return nil, fmt.Errorf("server pushed a bad ifconfig-ipv6 prefix %q", fields[1])
					}
				}
				p.localIP6, p.prefix6 = ip, n
			}
		case "route-gateway":
			if len(fields) >= 2 {
				p.gateway = net.ParseIP(fields[1])
			}
		case "peer-id":
			if len(fields) >= 2 {
				if n, err := strconv.Atoi(fields[1]); err == nil {
					p.peerID = uint32(n)
				}
			}
		case "cipher":
			if len(fields) >= 2 {
				p.cipher = fields[1]
			}
		case "tun-mtu":
			if len(fields) >= 2 {
				if n, err := strconv.Atoi(fields[1]); err == nil {
					p.mtu = n
				}
			}
		case "ping":
			// The server's own promise: "I will send a keepalive this often."
			// It is the only thing that makes inbound silence mean anything on
			// this protocol, because an OpenVPN ping is not echoed and there
			// is no request/response liveness to fall back on.
			if len(fields) >= 2 {
				if n, err := strconv.Atoi(fields[1]); err == nil && n > 0 {
					p.ping = time.Duration(n) * time.Second
				}
			}
		case "ping-restart":
			if len(fields) >= 2 {
				if n, err := strconv.Atoi(fields[1]); err == nil && n > 0 {
					p.pingRestart = time.Duration(n) * time.Second
				}
			}
		}
	}
	if p.localIP == nil {
		return nil, errors.New("server pushed no ifconfig address")
	}
	if p.netmask == nil {
		p.netmask = net.IPv4(255, 255, 255, 0)
	}
	if p.gateway == nil {
		p.gateway = p.localIP
	}
	return p, nil
}

// isNetmask reports whether an IPv4 value looks like a subnet mask rather than a
// peer address — a mask's leading octet is 255 (topology subnet), which a tunnel
// peer address is not.
func isNetmask(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && v4[0] == 255
}
