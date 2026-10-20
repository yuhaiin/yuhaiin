package lightweight

import "io"

// Reuse the existing worker and bounded queue. Drain only packets already
// available, without a timer or another goroutine waiting to form a batch.
func (s *Stack) writeBatchLoop(writer PacketBatchWriter) {
	limit := writer.PacketBatchSize()
	owned := make([]*ownedBuffer, limit)
	packets := make([]PacketBuffer, limit)
	defer func() {
		for _, b := range owned {
			b.release()
		}
	}()
	for {
		count := s.dequeueOutputBatch(owned)
		if count == 0 {
			return
		}
		for i, b := range owned[:count] {
			packets[i] = PacketBuffer{Data: b.data, Offset: b.offset, SegmentSize: b.segmentSize}
		}
		for start, attempt := 0, 0; start < count; {
			n, err := writer.WritePacketBatch(packets[start:count])
			if n < 0 || n > count-start {
				return
			}
			for i := start; i < start+n; i++ {
				owned[i].release()
				owned[i], packets[i] = nil, PacketBuffer{}
			}
			start += n
			s.packetsOut.Add(uint64(n))
			if start == count {
				break
			}
			if err == nil && n == 0 {
				err = io.ErrNoProgress
			}
			if n > 0 {
				attempt = 0
			}
			if err != nil {
				if !s.retryPacketIO(err, attempt) {
					return
				}
				attempt++
			}
		}
	}
}
