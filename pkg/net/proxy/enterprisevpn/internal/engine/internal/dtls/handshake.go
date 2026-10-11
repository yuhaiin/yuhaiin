package dtls

import (
	"encoding/binary"
	"fmt"
)

// DTLS handshake messages (RFC 6347 section 4.2.2).
//
//	 0      1..3      4..5         6..8            9..11        12..
//	+------+--------+------------+---------------+---------------+------+
//	| type | length | message_seq| fragment_offset| fragment_len | body |
//	+------+--------+------------+---------------+---------------+------+
//
// The three fields TLS does not have exist because UDP datagrams are bounded and
// lossy: a message longer than the path MTU is split across several records and
// reassembled by offset, and message_seq lets a receiver order and deduplicate
// the flights that arrive out of order or twice.
//
// The handshake transcript that Finished authenticates is over *unfragmented*
// messages, so a reassembled message must be hashed as though it had arrived
// whole, with fragment_offset zero and fragment_length equal to length.

// handshakeMsg is one complete handshake message.
type handshakeMsg struct {
	typ  uint8
	seq  uint16
	body []byte
}

// marshal renders the message unfragmented.
func (m handshakeMsg) marshal() []byte {
	out := make([]byte, 0, handshakeHeaderLen+len(m.body))
	out = append(out, m.typ)
	out = appendUint24(out, len(m.body))
	out = binary.BigEndian.AppendUint16(out, m.seq)
	out = appendUint24(out, 0)           // fragment_offset
	out = appendUint24(out, len(m.body)) // fragment_length
	return append(out, m.body...)
}

// fragments splits the message into pieces whose records fit within max octets
// of payload, which the caller sizes from the path MTU.
func (m handshakeMsg) fragments(max int) [][]byte {
	if max <= handshakeHeaderLen {
		return [][]byte{m.marshal()}
	}
	chunk := max - handshakeHeaderLen
	if len(m.body) <= chunk {
		return [][]byte{m.marshal()}
	}
	var out [][]byte
	for off := 0; off < len(m.body); off += chunk {
		end := min(off+chunk, len(m.body))
		frag := make([]byte, 0, handshakeHeaderLen+end-off)
		frag = append(frag, m.typ)
		frag = appendUint24(frag, len(m.body))
		frag = binary.BigEndian.AppendUint16(frag, m.seq)
		frag = appendUint24(frag, off)
		frag = appendUint24(frag, end-off)
		frag = append(frag, m.body[off:end]...)
		out = append(out, frag)
	}
	return out
}

// fragmentHeader is a parsed handshake fragment header.
type fragmentHeader struct {
	typ      uint8
	length   int
	seq      uint16
	offset   int
	fragLen  int
	body     []byte
	consumed int
}

func parseFragment(buf []byte) (fragmentHeader, error) {
	if len(buf) < handshakeHeaderLen {
		return fragmentHeader{}, fmt.Errorf("dtls: truncated handshake header")
	}
	h := fragmentHeader{
		typ:     buf[0],
		length:  int(uint24(buf[1:4])),
		seq:     binary.BigEndian.Uint16(buf[4:6]),
		offset:  int(uint24(buf[6:9])),
		fragLen: int(uint24(buf[9:12])),
	}
	end := handshakeHeaderLen + h.fragLen
	if h.fragLen < 0 || end > len(buf) {
		return fragmentHeader{}, fmt.Errorf("dtls: handshake fragment overruns its record")
	}
	if h.offset+h.fragLen > h.length {
		return fragmentHeader{}, fmt.Errorf("dtls: handshake fragment outside its message")
	}
	h.body = buf[handshakeHeaderLen:end]
	h.consumed = end
	return h, nil
}

// reassembler collects fragments into whole messages, in message_seq order.
type reassembler struct {
	next    uint16 // the message_seq we are waiting for
	partial map[uint16]*partialMsg
}

type partialMsg struct {
	typ    uint8
	body   []byte
	filled []bool // per-octet, so overlapping retransmissions converge correctly
	got    int
}

func newReassembler() *reassembler {
	return &reassembler{partial: map[uint16]*partialMsg{}}
}

// accept adds a fragment and returns any messages that are now complete and in
// order. A peer retransmits whole flights, so duplicate and overlapping
// fragments are normal and must be absorbed silently.
func (r *reassembler) accept(h fragmentHeader) ([]handshakeMsg, error) {
	if h.seq < r.next {
		return nil, nil // already processed; the peer is retransmitting
	}
	p, ok := r.partial[h.seq]
	if !ok {
		if h.length > maxHandshakeMsg {
			return nil, fmt.Errorf("dtls: handshake message of %d octets is too large", h.length)
		}
		p = &partialMsg{typ: h.typ, body: make([]byte, h.length), filled: make([]bool, h.length)}
		r.partial[h.seq] = p
	}
	if p.typ != h.typ || len(p.body) != h.length {
		return nil, fmt.Errorf("dtls: inconsistent fragments for message %d", h.seq)
	}
	copy(p.body[h.offset:], h.body)
	for i := h.offset; i < h.offset+h.fragLen; i++ {
		if !p.filled[i] {
			p.filled[i] = true
			p.got++
		}
	}

	var ready []handshakeMsg
	for {
		p, ok := r.partial[r.next]
		if !ok || p.got != len(p.body) {
			break
		}
		ready = append(ready, handshakeMsg{typ: p.typ, seq: r.next, body: p.body})
		delete(r.partial, r.next)
		r.next++
	}
	return ready, nil
}

// maxHandshakeMsg bounds a reassembly buffer, so a peer cannot make us allocate
// arbitrarily by claiming a huge message.
const maxHandshakeMsg = 1 << 16

func appendUint24(dst []byte, v int) []byte {
	return append(dst, byte(v>>16), byte(v>>8), byte(v))
}

func uint24(b []byte) uint32 {
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
}
