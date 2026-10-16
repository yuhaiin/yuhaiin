package lightweight

import (
	"slices"
	"time"
)

func (c *TCPConn) receive(seq uint32, data []byte, fin bool, now time.Time) {
	if c.recvFIN {
		c.sendACK()
		return
	}
	original := seq
	finSeq := seq + uint32(len(data))
	if before(seq, c.rcvNxt) {
		n := min(len(data), int(c.rcvNxt-seq))
		data = data[n:]
		seq += uint32(n)
	}
	if before(seq, c.rcvAdv) {
		data = data[:min(len(data), int(c.rcvAdv-seq))]
	} else {
		data = nil
	}
	if fin && (finSeq == c.rcvNxt || !before(finSeq, c.rcvNxt) && before(finSeq, c.rcvAdv)) {
		if !c.finPending || c.finSeq == finSeq {
			c.finPending = true
			c.finSeq = finSeq
		}
	}
	if c.finPending && after(seq+uint32(len(data)), c.finSeq) {
		if before(seq, c.finSeq) {
			data = data[:int(c.finSeq-seq)]
		} else {
			data = nil
		}
	}
	// First-arrival wins. Subtract existing intervals before allocating; malicious
	// overlaps and duplicates cannot multiply queue memory. The piece count and
	// byte budget independently bound metadata and payloads.
	additions := make([]receivePiece, 0, 4)
	cursor := seq
	end := seq + uint32(len(data))
	for _, v := range c.ooo {
		ve := v.seq + uint32(len(v.data))
		if !after(ve, cursor) {
			continue
		}
		if !before(v.seq, end) {
			break
		}
		if after(v.seq, cursor) {
			additions = append(additions, receivePiece{seq: cursor, data: data[int(cursor-seq):int(v.seq-seq)]})
		}
		if after(ve, cursor) {
			cursor = ve
		}
		if !before(cursor, end) {
			break
		}
	}
	if before(cursor, end) {
		additions = append(additions, receivePiece{seq: cursor, data: data[int(cursor-seq):]})
	}
	if len(additions)+len(c.ooo) > 128 && (len(additions) == 0 || additions[0].seq != c.rcvNxt) || len(additions)+len(c.ooo)+c.rx.len() > maxReceiveChunks {
		c.sendACK()
		return
	}
	for _, v := range additions {
		if len(v.data) > c.receiveLimit-c.rxBytes || !c.stack.reserve(receiveCharge) {
			c.stack.drops.Add(1)
			break
		}
		owner, err := c.stack.buffers.get(len(v.data))
		if err != nil {
			c.stack.release(receiveCharge)
			c.stack.drops.Add(1)
			break
		}
		b := owner.data
		copy(b, v.data)
		c.rxBytes += len(b)
		c.ooo = append(c.ooo, receivePiece{seq: v.seq, data: b, owner: owner})
	}
	slices.SortFunc(c.ooo, func(a, b receivePiece) int {
		if before(a.seq, b.seq) {
			return -1
		}
		if a.seq == b.seq {
			return 0
		}
		return 1
	})
	progressed := false
	for len(c.ooo) > 0 && c.ooo[0].seq == c.rcvNxt {
		v := c.ooo[0]
		c.ooo[0] = receivePiece{}
		c.ooo = c.ooo[1:]
		c.rcvNxt += uint32(len(v.data))
		progressed = true
		if c.readClosed {
			v.owner.release()
			c.stack.release(receiveCharge)
			c.rxBytes -= len(v.data)
		} else {
			c.rx.push(receiveChunk{data: v.data, owner: v.owner})
		}
	}
	if c.finPending && c.finSeq == c.rcvNxt {
		c.finPending = false
		c.recvFIN = true
		c.rcvNxt++
		progressed = true
		switch c.state {
		case Established:
			c.state = CloseWait
		case FinWait1:
			c.state = Closing
		case FinWait2:
			c.enterTimeWait(now)
		}
		// Any queued bytes beyond FIN are no longer part of this byte stream.
		for _, v := range c.ooo {
			v.owner.release()
			c.stack.release(receiveCharge)
			c.rxBytes -= len(v.data)
		}
		c.ooo = nil
	}
	if progressed {
		notify(&c.changed)
	}
	c.ackPending++
	if fin || original != seq || !progressed || len(c.ooo) > 0 || c.ackPending >= 2 || c.receiveWindow() == 0 {
		c.sendACK()
	} else if c.ackAt.IsZero() {
		c.ackAt = now.Add(20 * time.Millisecond)
	}
}
