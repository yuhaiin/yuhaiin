// Package reliable is OpenVPN's control-channel reliability algorithm: the
// sliding-window retransmitting sender and the reordering, acknowledging
// receiver that together turn UDP into the ordered, lossless byte stream the TLS
// handshake needs.
//
// It is deliberately decoupled from the wire format and from session IDs: it
// works in terms of message payloads and 32-bit packet IDs, so the retransmit,
// reorder, dedup and ACK logic can be tested without sockets or crypto. The
// control channel (which owns session IDs, wire encoding, and the net.Conn the
// TLS layer runs over) drives a Sender and a Receiver.
//
// OpenVPN numbers each side's control messages from 0, delivers them to TLS in
// strict ascending order, and acknowledges every one it receives — re-acking
// duplicates, since a lost ACK is why a peer retransmits (reliable.c, ssl_pkt.c).
package reliable

import "time"

// Defaults from OpenVPN. The window is --tls-window (4 by default): at most this
// many un-acknowledged control messages are outstanding at once. The timeout is
// the base control-channel retransmit interval (--tls-timeout, 1s).
const (
	DefaultWindow  = 4
	DefaultTimeout = time.Second
)

// Message is one reliable control payload and the ID assigned to it.
type Message struct {
	ID      uint32
	Payload []byte
}

// outgoing tracks a queued message's retransmission state.
type outgoing struct {
	Message
	lastSent time.Time
	everSent bool
}

// Sender is the transmit half: it assigns ascending IDs within a fixed window,
// retransmits un-acknowledged messages on a timeout, and releases them when the
// peer acknowledges.
type Sender struct {
	window   int
	timeout  time.Duration
	next     uint32
	inflight []*outgoing // ordered by ID, oldest first
}

// NewSender creates a Sender with the given in-flight window and retransmit
// timeout; zero values fall back to the OpenVPN defaults.
func NewSender(window int, timeout time.Duration) *Sender {
	if window <= 0 {
		window = DefaultWindow
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Sender{window: window, timeout: timeout}
}

// Queue buffers a payload for reliable delivery and returns its assigned ID. It
// reports false without queueing when the in-flight window is full, so the
// caller waits for ACKs before offering more.
func (s *Sender) Queue(payload []byte) (uint32, bool) {
	if len(s.inflight) >= s.window {
		return 0, false
	}
	id := s.next
	s.next++
	s.inflight = append(s.inflight, &outgoing{Message: Message{ID: id, Payload: payload}})
	return id, true
}

// Ready reports whether the window has room for another Queue.
func (s *Sender) Ready() bool { return len(s.inflight) < s.window }

// InFlight is the number of un-acknowledged messages outstanding.
func (s *Sender) InFlight() int { return len(s.inflight) }

// Ack releases an acknowledged message from the window. Unknown IDs (a duplicate
// ACK, or an ACK for something already released) are ignored.
func (s *Sender) Ack(id uint32) {
	for i, m := range s.inflight {
		if m.ID == id {
			s.inflight = append(s.inflight[:i], s.inflight[i+1:]...)
			return
		}
	}
}

// Due returns the messages that should be transmitted at now: any not yet sent,
// and any whose retransmit timeout has elapsed. It records them as sent at now,
// so a message is returned again only after another timeout.
func (s *Sender) Due(now time.Time) []Message {
	var due []Message
	for _, m := range s.inflight {
		if !m.everSent || now.Sub(m.lastSent) >= s.timeout {
			m.everSent = true
			m.lastSent = now
			due = append(due, m.Message)
		}
	}
	return due
}

// NextDue reports how long until the soonest retransmission is due, for
// scheduling a wakeup. It returns 0 when a message is waiting to be sent for the
// first time, and ok=false when nothing is in flight.
func (s *Sender) NextDue(now time.Time) (wait time.Duration, ok bool) {
	if len(s.inflight) == 0 {
		return 0, false
	}
	min := s.timeout
	for _, m := range s.inflight {
		if !m.everSent {
			return 0, true
		}
		if d := s.timeout - now.Sub(m.lastSent); d < min {
			min = d
		}
	}
	if min < 0 {
		min = 0
	}
	return min, true
}

// Receiver is the receive half: it deduplicates incoming messages, buffers those
// that arrive out of order, delivers payloads to TLS in strict ID order, and
// tracks which IDs still need acknowledging.
type Receiver struct {
	next     uint32            // next ID to deliver in order
	buffered map[uint32][]byte // received at or beyond next, not yet deliverable
	pending  []uint32          // IDs to acknowledge, in arrival order
}

// NewReceiver creates an empty Receiver expecting message ID 0 first.
func NewReceiver() *Receiver {
	return &Receiver{buffered: make(map[uint32][]byte)}
}

// Receive records an incoming message and returns any payloads that in-order
// delivery now makes available (possibly several, when a gap is filled). Every
// received ID is queued for acknowledgement, including duplicates — a peer only
// retransmits because it did not hear our earlier ACK.
func (r *Receiver) Receive(id uint32, payload []byte) [][]byte {
	r.pending = append(r.pending, id)
	if id < r.next {
		return nil // already delivered; the ACK above is what it wants
	}
	if _, dup := r.buffered[id]; dup {
		return nil
	}
	// Copy: payload aliases a decode buffer the caller reuses.
	r.buffered[id] = append([]byte(nil), payload...)

	var out [][]byte
	for {
		p, ok := r.buffered[r.next]
		if !ok {
			break
		}
		out = append(out, p)
		delete(r.buffered, r.next)
		r.next++
	}
	return out
}

// HasACKs reports whether any acknowledgements are pending.
func (r *Receiver) HasACKs() bool { return len(r.pending) > 0 }

// TakeACKs removes and returns up to max pending acknowledgement IDs, oldest
// first, for packing into an outgoing packet. OpenVPN caps the ACK array per
// packet, so a caller drains a bounded number at a time.
func (r *Receiver) TakeACKs(max int) []uint32 {
	if max <= 0 || len(r.pending) == 0 {
		return nil
	}
	if max > len(r.pending) {
		max = len(r.pending)
	}
	acks := r.pending[:max:max]
	r.pending = r.pending[max:]
	return acks
}
