package transport

// replayFilter is the sliding-window anti-replay check from RFC 6479, the same
// algorithm WireGuard's own implementations use. It accepts each counter at most
// once and rejects any that has fallen more than a window behind the highest
// seen, so a captured transport packet cannot be re-injected.
//
// The window is a ring of 64-bit blocks. Advancing to a higher counter clears
// only the blocks the window has moved past, so the cost is bounded regardless
// of how far ahead the new counter is — an out-of-order path that jumps forward
// does not walk the whole ring.
const (
	replayBlockBitLog = 6                      // 1<<6 == 64 bits per block
	replayBlockBits   = 1 << replayBlockBitLog // bits in one ring block
	replayRingBlocks  = 1 << 7                 // ring length (power of two)
	replayWindowSize  = (replayRingBlocks - 1) * replayBlockBits
	replayBlockMask   = replayRingBlocks - 1
	replayBitMask     = replayBlockBits - 1
)

type replayFilter struct {
	last uint64
	ring [replayRingBlocks]uint64
}

// validate reports whether counter is fresh, and records it if so. A false
// result means the counter is a replay or has fallen behind the window; the
// caller must already have authenticated the packet, since an unauthenticated
// counter must never move the window.
func (f *replayFilter) validate(counter uint64) bool {
	indexBlock := counter >> replayBlockBitLog

	switch {
	case counter > f.last:
		// The window moves forward. Clear the blocks between the old head and
		// the new one, capped at a full ring — beyond that every block is stale
		// and will be cleared anyway.
		current := f.last >> replayBlockBitLog
		diff := min(indexBlock-current, replayRingBlocks)
		for i := current + 1; i <= current+diff; i++ {
			f.ring[i&replayBlockMask] = 0
		}
		f.last = counter
	case f.last-counter > replayWindowSize:
		// Too far behind the window to judge; treat as a replay.
		return false
	}

	indexBlock &= replayBlockMask
	bit := uint64(1) << (counter & replayBitMask)
	old := f.ring[indexBlock]
	f.ring[indexBlock] = old | bit
	// If the bit was already set, this counter has been seen.
	return old&bit == 0
}
