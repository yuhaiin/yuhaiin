package lightweight

import (
	"encoding/binary"
	"sync"
	"time"
)

type fragmentKey struct {
	src, dst [16]byte
	v4       bool
	id       uint32
	proto    uint8
}
type fragmentPiece struct {
	offset int
	data   []byte
}
type fragmentGroup struct {
	expires  time.Time
	parts    []fragmentPiece
	end      int
	poisoned bool
	bytes    int
}
type fragmentTable struct {
	mu     sync.Mutex
	stack  *Stack
	groups map[fragmentKey]*fragmentGroup
	bytes  int
	job    timerJob
}

func (f *fragmentTable) init(s *Stack) {
	f.stack = s
	f.groups = make(map[fragmentKey]*fragmentGroup)
	f.job = timerJob{index: -1, run: f.expire}
}
func (f *fragmentTable) schedule() {
	var at time.Time
	for _, g := range f.groups {
		at = earliest(at, g.expires)
	}
	f.stack.scheduler.set(&f.job, at)
}
func (f *fragmentTable) discard(g *fragmentGroup) {
	f.stack.release(g.bytes + len(g.parts)*receiveCharge)
	f.bytes -= g.bytes
	g.parts = nil
	g.bytes = 0
	g.poisoned = true
}
func (f *fragmentTable) expire(now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, g := range f.groups {
		if !now.Before(g.expires) {
			f.discard(g)
			f.stack.release(256)
			delete(f.groups, k)
		}
	}
	f.schedule()
}
func (f *fragmentTable) close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, g := range f.groups {
		f.discard(g)
		f.stack.release(256)
		delete(f.groups, k)
	}
	f.stack.scheduler.set(&f.job, time.Time{})
}
func (f *fragmentTable) add(p Packet) (Packet, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stack.closed() {
		return Packet{}, false, ErrLimit
	}
	k := fragmentKey{p.Source.As16(), p.Destination.As16(), p.Source.Is4(), p.FragmentID, p.Protocol}
	g := f.groups[k]
	if g == nil {
		if len(f.groups) >= f.stack.config.MaxFragmentGroups {
			return Packet{}, false, ErrLimit
		}
		if !f.stack.reserve(256) {
			return Packet{}, false, ErrLimit
		}
		g = &fragmentGroup{expires: time.Now().Add(f.stack.config.FragmentTimeout), end: -1}
		f.groups[k] = g
		f.schedule()
	}
	if g.poisoned {
		return Packet{}, false, ErrMalformed
	}
	start, end := p.FragmentOffset, p.FragmentOffset+len(p.Payload)
	if g.end >= 0 && end > g.end || !p.MoreFragments && g.end >= 0 && end != g.end {
		f.discard(g)
		return Packet{}, false, ErrMalformed
	}
	for _, v := range g.parts {
		if start < v.offset+len(v.data) && v.offset < end {
			f.discard(g)
			return Packet{}, false, ErrMalformed
		}
		if !p.MoreFragments && v.offset+len(v.data) > end {
			f.discard(g)
			return Packet{}, false, ErrMalformed
		}
	}
	if len(g.parts) >= 128 || len(p.Payload) > f.stack.config.MaxFragmentBytes-f.bytes || !f.stack.reserve(len(p.Payload)+receiveCharge) {
		f.discard(g)
		return Packet{}, false, ErrLimit
	}
	b := make([]byte, len(p.Payload))
	copy(b, p.Payload)
	g.parts = append(g.parts, fragmentPiece{start, b})
	g.bytes += len(b)
	f.bytes += len(b)
	if !p.MoreFragments {
		g.end = end
	}
	if g.end < 0 || g.bytes != g.end {
		return Packet{}, false, nil
	}
	payload := make([]byte, g.end)
	for _, v := range g.parts {
		copy(payload[v.offset:], v.data)
	}
	f.discard(g)
	f.stack.release(256)
	delete(f.groups, k)
	f.schedule()
	data, err := makeIP(p.Source, p.Destination, p.Protocol, payload, uint16(p.FragmentID))
	if err != nil {
		return Packet{}, false, err
	}
	assembled, err := ParsePacket(data)
	// A second Fragment header in the reconstructed IPv6 fragmentable part is
	// invalid, not a request to recurse into another unbounded reassembly table.
	if err == nil && assembled.Fragmented {
		err = ErrMalformed
	}
	return assembled, err == nil, err
}

func (s *Stack) sendDatagram(src, dst flowAddress, proto uint8, payload []byte) error {
	// Fragmentation is only for connectionless IP output. TCP uses MSS/PMTUD.
	b, err := makeIP(src.addr, dst.addr, proto, payload, uint16(s.nextID.Add(1)))
	if err != nil {
		return err
	}
	if len(b) <= s.config.MTU {
		return s.emit(b)
	}
	h := 20
	if src.addr.Is6() {
		h = 48
	}
	size := (s.config.MTU - h) &^ 7
	id := s.nextID.Add(1)
	for off := 0; off < len(payload); off += size {
		end := min(len(payload), off+size)
		more := end < len(payload)
		var packet []byte
		if src.addr.Is4() {
			packet, err = makeIP(src.addr, dst.addr, proto, payload[off:end], uint16(id))
			if err != nil {
				return err
			}
			flags := uint16(off / 8)
			if more {
				flags |= 0x2000
			}
			binary.BigEndian.PutUint16(packet[6:8], flags)
			packet[10] = 0
			packet[11] = 0
			binary.BigEndian.PutUint16(packet[10:12], Checksum(packet[:20]))
		} else {
			frag := make([]byte, 8+end-off)
			frag[0] = proto
			flags := uint16(off)
			if more {
				flags |= 1
			}
			binary.BigEndian.PutUint16(frag[2:4], flags)
			binary.BigEndian.PutUint32(frag[4:8], id)
			copy(frag[8:], payload[off:end])
			packet, err = makeIP(src.addr, dst.addr, 44, frag, uint16(id))
			if err != nil {
				return err
			}
		}
		if err = s.emit(packet); err != nil {
			return err
		}
	}
	return nil
}
