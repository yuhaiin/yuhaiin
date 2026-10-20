package lightweight

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"maps"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
)

// PacketIO transfers complete IP packets, without link/virtio headers. ReadPacket
// may borrow its buffer only until return; WritePacket may borrow until return.
// Exactly one reader and one writer run concurrently. Close MUST interrupt both.
// Complete-packet implementations need no offload awareness. Optional packet
// views and prefixed/GSO writes are negotiated through the interfaces in packetio.go.
type PacketIO interface {
	ReadPacket([]byte) (int, error)
	WritePacket([]byte) error
	Close() error
}

type flowKey struct{ local, remote netip.AddrPort }
type flowShard struct {
	sync.Mutex
	flows map[flowKey]*TCPConn
}

// Includes the connection, built-in controller, IO/handshake signals, control
// descriptors and small retained queue arrays. Payloads and live queue entries
// are charged separately.
const connectionCharge = 6144

type Stack struct {
	buffers                                       bufferPool
	outputMu                                      sync.Mutex
	outputCount                                   atomic.Int64
	outputWaiters                                 outputQueue
	config                                        Config
	link                                          PacketIO
	packetWriter                                  PacketBufferWriter
	headroom, gsoMax                              int
	done                                          chan struct{}
	once                                          sync.Once
	txMu                                          sync.RWMutex
	wg                                            sync.WaitGroup
	closeErr                                      error
	scheduler                                     *scheduler
	output                                        trafficcontrol.OutputQueue[*ownedBuffer]
	inputGovernor                                 *trafficcontrol.Governor
	forwarded                                     chan Datagram
	pings                                         chan *PingRequest
	shards                                        [32]flowShard
	mu                                            sync.Mutex
	listeners                                     map[netip.AddrPort]*TCPListener
	udp                                           map[netip.AddrPort]*UDPConn
	fragments                                     fragmentTable
	nextPort                                      atomic.Uint32
	nextID                                        atomic.Uint32
	flows                                         atomic.Int64
	memory                                        atomic.Int64
	packetsIn, packetsOut, drops, retransmissions atomic.Uint64
	icmpMu                                        sync.Mutex
	icmpTokens                                    float64
	icmpStamp                                     int64
}
type Statistics struct {
	MemoryBytes, Connections                            int64
	OutputQueuedPackets, OutputQueuedBytes              int64
	OutputAQMDrops, OutputRejected, OutputOverloadDrops uint64
	CachedBytes                                         int64
	PacketsIn, PacketsOut, Drops, Retransmissions       uint64
}

// TrafficControlQueue exposes bounded scheduler diagnostics without leaking
// packet identities or the concrete queue implementation to an adapter.
func (s *Stack) TrafficControlQueue() (trafficcontrol.FairStats, bool) {
	if s.output == nil {
		return trafficcontrol.FairStats{}, false
	}
	return s.output.Stats(), true
}

func (s *Stack) Stats() Statistics {
	stats := Statistics{MemoryBytes: s.memory.Load(), Connections: s.flows.Load(), CachedBytes: s.buffers.cached.Load(), PacketsIn: s.packetsIn.Load(), PacketsOut: s.packetsOut.Load(), Drops: s.drops.Load(), Retransmissions: s.retransmissions.Load()}
	if s.output != nil {
		q := s.output.Stats()
		stats.OutputQueuedPackets, stats.OutputQueuedBytes = q.Packets, q.Bytes
		stats.OutputAQMDrops, stats.OutputRejected = q.DroppedAQM, q.Rejected
		stats.OutputOverloadDrops = q.DroppedOverload
	}
	return stats
}

// New takes ownership of link only on success. Close joins all stack workers.
func New(config Config, link PacketIO) (*Stack, error) {
	c, err := config.normalize()
	if err != nil {
		return nil, err
	}
	if link == nil {
		return nil, errors.New("lightweight: nil PacketIO")
	}
	s := &Stack{config: c, link: link, done: make(chan struct{}), forwarded: make(chan Datagram, min(c.QueuePackets, 256)), listeners: make(map[netip.AddrPort]*TCPListener), udp: make(map[netip.AddrPort]*UDPConn), icmpTokens: 100}
	if writer, ok := link.(PacketBufferWriter); ok {
		s.headroom, s.gsoMax = writer.Headroom(), writer.MaxGSOPacketSize()
		if s.headroom < 0 || s.headroom > maxPacketHeadroom || s.gsoMax < 0 || s.gsoMax > 65535 || s.gsoMax > 0 && s.gsoMax < c.MTU {
			return nil, errors.New("lightweight: invalid packet writer capabilities")
		}
		s.packetWriter = writer
	}
	if writer, ok := link.(PacketBatchWriter); ok && (writer.PacketBatchSize() < 1 || writer.PacketBatchSize() > 128) {
		return nil, errors.New("lightweight: invalid packet batch size")
	}
	if c.ForwardPing {
		s.pings = make(chan *PingRequest, min(c.QueuePackets, 64))
	}
	// A host group receives an aggregate DRR share regardless of how many
	// simultaneous TCP/UDP tuples it opens. Within each group FQ-CoDel
	// preserves per-flow isolation and bounded sojourn.
	s.initOutput(c.OutputScheduler, c.QueuePackets, max(int64(c.MTU)*int64(c.QueuePackets), c.MemoryLimit/8))
	if c.InputPacketsPerSecond > 0 {
		s.inputGovernor = trafficcontrol.NewGovernor(trafficcontrol.Limits{PacketsPerSec: float64(c.InputPacketsPerSecond), PacketBurst: float64(c.InputPacketBurst)}, nil)
	}
	s.scheduler = newScheduler(s.done)
	s.buffers.init(s)
	s.fragments.init(s)
	for i := range s.shards {
		s.shards[i].flows = make(map[flowKey]*TCPConn)
	}
	var seed [4]byte
	_, _ = rand.Read(seed[:])
	s.nextPort.Store(binary.BigEndian.Uint32(seed[:]) % 16384)
	s.wg.Go(s.scheduler.loop)
	s.wg.Go(s.readLoop)
	s.wg.Go(s.writeLoop)
	return s, nil
}
func (s *Stack) Done() <-chan struct{} { return s.done }
func (s *Stack) closed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}
func (s *Stack) reserve(n int) bool {
	for {
		old := s.memory.Load()
		if int64(n) > s.config.MemoryLimit-old {
			if s.buffers.trim(n) {
				continue
			}
			return false
		}
		if s.memory.CompareAndSwap(old, old+int64(n)) {
			return true
		}
	}
}
func (s *Stack) release(n int) { s.memory.Add(-int64(n)); s.wakeOutput() }
func (s *Stack) shutdown() {
	s.once.Do(func() {
		s.txMu.Lock()
		close(s.done)
		s.output.Close()
		s.txMu.Unlock()
		s.closeErr = s.link.Close()
		// Publish closed before taking table snapshots. Registrations check under
		// the table lock, so none can appear after their respective snapshot.
		for i := range s.shards {
			sh := &s.shards[i]
			sh.Lock()
			cs := slices.Collect(maps.Values(sh.flows))
			sh.Unlock()
			for _, c := range cs {
				c.abort(net.ErrClosed)
			}
		}
		s.mu.Lock()
		us := slices.Collect(maps.Values(s.udp))
		ls := slices.Collect(maps.Values(s.listeners))
		s.mu.Unlock()
		for _, u := range us {
			_ = u.Close()
		}
		for _, l := range ls {
			_ = l.Close()
		}
		s.fragments.close()
	})
}
func (s *Stack) Close() error {
	s.shutdown()
	s.wg.Wait()
	for _, p := range s.output.Drain() {
		p.release()
	}
	for {
		select {
		case p := <-s.forwarded:
			s.release(len(p.Payload) + receiveCharge)
		default:
			goto pings
		}
	}
pings:
	for {
		select {
		case p := <-s.pings:
			s.release(len(p.packet) + pingCharge)
		default:
			s.buffers.close()
			return s.closeErr
		}
	}
}
func (s *Stack) readLoop() {
	defer s.shutdown()
	var read func() ([]byte, bool, error)
	if reader, ok := s.link.(PacketViewReader); ok {
		read = reader.ReadPacketView
	} else {
		b := make([]byte, 65575)
		read = func() ([]byte, bool, error) {
			n, err := s.link.ReadPacket(b)
			if n < 0 || n > len(b) {
				return nil, false, io.ErrShortBuffer
			}
			return b[:n], false, err
		}
	}
	attempts := 0
	var processed uint32
	for {
		b, verified, err := read()
		if len(b) > 0 && len(b) <= 65575 {
			s.packetsIn.Add(1)
			processed++
			if processed&255 == 0 {
				runtime.Gosched()
			} // Yield during sustained PPS floods.
			if s.inputGovernor != nil && !s.inputGovernor.AdmitPacket(time.Now()) {
				s.drops.Add(1)
				continue
			}
			if e := s.inputVerified(b, verified); e != nil {
				s.drops.Add(1)
			}
		}
		if err != nil {
			if s.retryPacketIO(err, attempts) {
				attempts++
				continue
			}
			// A too-large packet has already been consumed/dropped by the device.
			if errors.Is(err, io.ErrShortBuffer) && !s.closed() {
				s.drops.Add(1)
				continue
			}
			return
		}
		if len(b) == 0 || len(b) > 65575 {
			return
		}
		attempts = 0
	}
}
func (s *Stack) writeLoop() {
	defer s.shutdown()
	if writer, ok := s.link.(PacketBatchWriter); ok && writer.PacketBatchSize() > 1 {
		s.writeBatchLoop(writer)
		return
	}
	var owned [32]*ownedBuffer
	defer func() {
		for _, b := range owned {
			b.release()
		}
	}()
	for {
		n := s.dequeueOutputBatch(owned[:])
		if n == 0 {
			return
		}
		for i, b := range owned[:n] {
			write := func() error {
				if s.packetWriter != nil {
					return s.packetWriter.WritePacketBuffer(b.data, b.offset, b.segmentSize)
				}
				return s.link.WritePacket(b.data[b.offset:])
			}
			err := write()
			for attempt := 0; err != nil && s.retryPacketIO(err, attempt); attempt++ {
				err = write()
			}
			b.release()
			owned[i] = nil
			if err != nil {
				return
			}
			s.packetsOut.Add(1)
		}
	}
}

// emit copies unowned packet data; the owned fast path transfers its lease.
func (s *Stack) emit(b []byte) error {
	packet, err := s.buffers.get(s.headroom + len(b))
	if err != nil {
		return err
	}
	packet.offset = s.headroom
	copy(packet.data[packet.offset:], b)
	if err = s.emitOwned(packet); err != nil {
		packet.release()
	}
	return err
}
func (s *Stack) emitOwned(packet *ownedBuffer) error {
	s.txMu.RLock()
	defer s.txMu.RUnlock()
	if s.closed() {
		return net.ErrClosed
	}
	if s.output.Enqueue(packet) {
		return nil
	}
	return ErrLimit
}

func (s *Stack) ipBuffer(src, dst netip.Addr, proto uint8, payloadSize int) (*ownedBuffer, int, error) {
	h, err := ipHeaderSize(src, dst, payloadSize)
	if err != nil {
		return nil, 0, err
	}
	packet, err := s.buffers.get(s.headroom + h + payloadSize)
	if err != nil {
		return nil, s.headroom + h, err
	}
	packet.offset = s.headroom
	fillIPHeader(packet.data[packet.offset:], src, dst, proto, uint16(s.nextID.Add(1)), h)
	return packet, packet.offset + h, nil
}
func (s *Stack) sendIP(src, dst netip.Addr, proto uint8, payload []byte) error {
	h, err := ipHeaderSize(src, dst, len(payload))
	if err != nil {
		return err
	}
	if h+len(payload) > s.config.MTU {
		return ErrMTU
	}
	packet, h, err := s.ipBuffer(src, dst, proto, len(payload))
	if err != nil {
		return err
	}
	copy(packet.data[h:], payload)
	if err = s.emitOwned(packet); err != nil {
		packet.release()
	}
	return err
}
func (s *Stack) input(b []byte) error {
	return s.inputVerified(b, false)
}
func (s *Stack) inputVerified(b []byte, checksumVerified bool) error {
	p, err := ParsePacket(b)
	if err != nil {
		return err
	}
	if p.Source.IsUnspecified() || p.Source.IsMulticast() || p.Destination.IsMulticast() || p.Destination.IsUnspecified() {
		return ErrUnsupported
	}
	if !s.config.Promiscuous && !s.local(p.Destination) {
		return ErrUnsupported
	}
	if p.HopLimit == 0 {
		s.icmpError(p, 11, 0, 0)
		return ErrMalformed
	}
	if p.Fragmented {
		checksumVerified = false // Fragment reassembly produces a new complete packet.
		var complete bool
		p, complete, err = s.fragments.add(p)
		if err != nil || !complete {
			return err
		}
	}
	if err := p.validateTransport(checksumVerified); err != nil {
		return err
	}
	switch p.Protocol {
	case 6:
		s.handleTCP(p)
	case 17:
		s.handleUDP(p)
	case 1, 58:
		s.handleICMP(p)
	default:
		return ErrUnsupported
	}
	return nil
}
func (s *Stack) local(a netip.Addr) bool {
	return slices.Contains(s.config.Addresses, a)
}
func (s *Stack) source(remote netip.Addr) (netip.Addr, error) {
	for _, v := range s.config.Addresses {
		if remote.Is4() == v.Is4() {
			return v, nil
		}
	}
	return netip.Addr{}, errors.New("lightweight: no source address for family")
}
func (s *Stack) shard(k flowKey) *flowShard {
	a := k.local.Addr().As16()
	b := k.remote.Addr().As16()
	return &s.shards[(uint32(k.local.Port())^uint32(k.remote.Port())^uint32(a[15])^uint32(b[15]))%32]
}
func (s *Stack) find(k flowKey) *TCPConn {
	sh := s.shard(k)
	sh.Lock()
	c := sh.flows[k]
	sh.Unlock()
	return c
}
func (s *Stack) add(c *TCPConn) error {
	sh := s.shard(c.key)
	sh.Lock()
	defer sh.Unlock()
	if s.closed() {
		return net.ErrClosed
	}
	if sh.flows[c.key] != nil {
		return errors.New("lightweight: tuple in use")
	}
	if s.flows.Add(1) > int64(s.config.MaxConnections) {
		s.flows.Add(-1)
		return ErrLimit
	}
	if !s.reserve(connectionCharge) {
		s.flows.Add(-1)
		return ErrLimit
	}
	sh.flows[c.key] = c
	return nil
}
func (s *Stack) remove(c *TCPConn) {
	sh := s.shard(c.key)
	sh.Lock()
	if sh.flows[c.key] == c {
		delete(sh.flows, c.key)
		s.flows.Add(-1)
		s.release(connectionCharge)
	}
	sh.Unlock()
}
func (s *Stack) port() uint16 { return uint16(49152 + s.nextPort.Add(1)%16384) }
