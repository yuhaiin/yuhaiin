package l2tp

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight"
)

// tcpPacketTrace records only IP/TCP headers at the L2TP/stack boundary.
// No application payload, PPP authentication material or raw pcap is retained.
type tcpPacketTrace struct {
	mu      sync.Mutex
	entries []TCPPacketEvent
	next    int
	wrapped bool
}

type TCPPacketEvent struct {
	Time       time.Time `json:"time"`
	Direction  string    `json:"direction"`
	Source     string    `json:"source"`
	Dest       string    `json:"destination"`
	Seq        uint32    `json:"seq"`
	ACK        uint32    `json:"ack"`
	Flags      uint8     `json:"flags"`
	Window     uint16    `json:"window"`
	PayloadLen int       `json:"payload_length"`
}

func newTCPPacketTrace(limit int) *tcpPacketTrace {
	return &tcpPacketTrace{entries: make([]TCPPacketEvent, 0, limit)}
}

func (r *tcpPacketTrace) record(direction string, raw []byte) {
	if r == nil {
		return
	}
	p, err := lightweight.ParsePacket(raw)
	if err != nil || p.Protocol != 6 || p.Fragmented || len(p.Payload) < 20 {
		return
	}
	b := p.Payload
	h := int(b[12]>>4) * 4
	if h < 20 || h > len(b) {
		return
	}
	event := TCPPacketEvent{
		Time: time.Now().UTC(), Direction: direction,
		Source: netip.AddrPortFrom(p.Source, binary.BigEndian.Uint16(b[:2])).String(),
		Dest: netip.AddrPortFrom(p.Destination, binary.BigEndian.Uint16(b[2:4])).String(),
		Seq: binary.BigEndian.Uint32(b[4:8]),
		ACK: binary.BigEndian.Uint32(b[8:12]),
		Flags: b[13],
		Window: binary.BigEndian.Uint16(b[14:16]),
		PayloadLen: len(b) - h,
	}
	r.mu.Lock()
	if len(r.entries) < cap(r.entries) {
		r.entries = append(r.entries, event)
	} else {
		r.entries[r.next] = event
		r.wrapped = true
	}
	r.next = (r.next + 1) % cap(r.entries)
	r.mu.Unlock()
}

func (r *tcpPacketTrace) snapshot() []TCPPacketEvent {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.wrapped {
		return append([]TCPPacketEvent(nil), r.entries...)
	}
	out := make([]TCPPacketEvent, 0, len(r.entries))
	out = append(out, r.entries[r.next:]...)
	return append(out, r.entries[:r.next]...)
}
