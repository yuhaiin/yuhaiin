package nat

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

func (u *SourceControl) loopWriteBack(p *wrapConn, dst netapi.Address) {
	closed := make(chan struct{})
	stopClose := context.AfterFunc(u.ctx, func() { _ = p.Close(); close(closed) })
	defer func() {
		if !stopClose() {
			<-closed
		}
		_ = p.Close()
		u.loopStopTime.Store(new(time.Now()))
		u.readers.Add(-1)
	}()
	// Read a complete UDP datagram even when UDPBufferSize is configured for
	// ordinary MTU-sized traffic. Keep only a payload-sized pooled allocation
	// in the reply queue, rather than retaining 64 KiB for every small packet.
	scratch := pool.GetBytes(pool.MaxSegmentSize)
	defer pool.PutBytes(scratch)
	for {
		p.refreshReadDeadline(udpIdleTimeout())
		n, from, err := p.ReadFrom(scratch)
		if err != nil {
			if ignoreError(err) {
				log.Debug("read from proxy break", "err", err, "dst", dst)
			} else {
				log.Error("read from proxy failed", "err", err, "dst", dst)
			}
			return
		}
		metrics.Counter.AddReceiveUDPPacket()
		metrics.Counter.AddReceiveUDPPacketSize(n)
		if u.access != nil {
			original, _ := p.mapper.replyAddr(from).(netapi.Address)
			if err := u.access.Authorize(original, from); err != nil {
				metrics.Counter.AddReceiveUDPDroppedPacket()
				continue
			}
		}
		if !u.queueBudget.ReserveQueueBytes(int64(n)) {
			metrics.Counter.AddReceiveUDPDroppedPacket()
			continue
		}
		data := pool.Clone(scratch[:n])
		if !u.receivedPackets.Push(sentPacket{from: p.mapper.replyAddr(from), real: from, buf: data, conn: p}) {
			u.queueBudget.ReleaseQueueBytes(int64(len(data)))
			pool.PutBytes(data)
			metrics.Counter.AddReceiveUDPDroppedPacket()
			continue
		}
		select {
		case u.notifyReceivedPacket <- struct{}{}:
		default:
		}
	}
}

func ignoreError(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
}
