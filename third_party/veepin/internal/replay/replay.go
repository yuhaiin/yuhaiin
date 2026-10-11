// Package replay implements the sliding-window anti-replay check shared by
// protocols whose data path uses a monotonic counter as both the replay
// identifier and the AEAD nonce.
//
// # Why this is not used by every protocol here
//
// The tree contains several other implementations of what looks like the same
// algorithm — in internal/ikev2/esp, internal/dtls, internal/wireguard/transport
// and two in internal/openvpn. They are deliberately left alone.
//
// They are not the same algorithm wearing different names. ESP's window is
// RFC 4303's, with its mandated size and sequence handling; DTLS's is per-epoch;
// WireGuard's follows the protocol paper; the two OpenVPN variants differ from
// each other. Each is correct and verified by interop cells against a real
// third-party peer, and the parameterisation needed to cover all of them would
// be more complex than any one of them. Replacing working, independently
// verified code with a shared abstraction would trade real correctness for an
// aesthetic gain.
//
// What this package does cover is the genuine duplicate: internal/nebula and
// internal/toy had byte-for-byte the same window, written twice, including the
// same fiddly step of clearing the slots the window slides past. That step is
// easy to get subtly wrong, and getting it wrong means either accepting replays
// or dropping legitimate traffic — neither of which a test notices unless it is
// looking.
//
// If you are adding a protocol whose replay rule is "a counter, a window, and
// nothing else", use this. If your protocol's specification says something more
// specific, write that instead and leave a note saying why, as the packages
// above do.
package replay

// Size is how far behind the highest counter a late packet is still accepted.
//
// UDP reorders, so a strictly-increasing check would drop real traffic. 1024
// matches what ESP and nebula use and is far wider than any reordering a real
// network produces.
const Size = 1024

// Window tracks which counters have been accepted. The zero value is not usable;
// call New. It is not safe for concurrent use — callers hold whatever lock
// already protects their session state.
type Window struct {
	highest uint64
	seen    []bool
}

// New returns a window of the default size.
func New() *Window { return NewSize(Size) }

// NewSize returns a window tracking n counters behind the highest seen.
func NewSize(n int) *Window {
	if n <= 0 {
		n = Size
	}
	return &Window{seen: make([]bool, n)}
}

// Accept records a counter, reporting false if it is a replay or too old to
// judge.
//
// It must be called only after the packet has authenticated. Admitting an
// unauthenticated counter would let anyone able to send a datagram advance the
// window and lock the real peer out of its own session — which is the whole
// reason the ordering matters, and the reason this function is named for what
// it decides rather than for what it stores.
func (w *Window) Accept(counter uint64) bool {
	n := uint64(len(w.seen))

	switch {
	case counter > w.highest:
		// Clear the slots the window slides past. Without this, a counter that
		// never arrived would be mistaken for one that did as soon as the
		// counter space wraps around the bitmap -- silently rejecting valid
		// traffic much later, in a way that looks like packet loss.
		gap := counter - w.highest
		if gap >= n {
			for i := range w.seen {
				w.seen[i] = false
			}
		} else {
			for i := w.highest + 1; i <= counter; i++ {
				w.seen[i%n] = false
			}
		}
		w.seen[counter%n] = true
		w.highest = counter
		return true

	case w.highest-counter >= n:
		// Older than the window: indistinguishable from a replay, so refused.
		return false

	default:
		if w.seen[counter%n] {
			return false
		}
		w.seen[counter%n] = true
		return true
	}
}

// MarkSeen records counters consumed before the data path started — the
// handshake's own messages — so they are not later mistaken for traffic that
// went missing.
func (w *Window) MarkSeen(upTo uint64) {
	for i := uint64(1); i <= upTo; i++ {
		w.Accept(i)
	}
}

// Highest is the largest counter accepted so far.
func (w *Window) Highest() uint64 { return w.highest }
