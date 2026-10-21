package nat

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

func sameReplySource(a, b net.Addr) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	// TCP/HTTP2 remote addresses are normally stable, comparable values or
	// pointers. Avoid String/ParseSysAddr allocations on that packet path.
	if reflect.TypeOf(a) == reflect.TypeOf(b) && reflect.TypeOf(a).Comparable() {
		return a == b
	}
	return a.Network() == b.Network() && a.String() == b.String()
}

func (u *SourceControl) writeReply(ctx context.Context, data []byte, addr net.Addr) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		binding := u.reply.Load()
		_, err := binding.write(binding.ctx, data, addr)
		if err == nil || binding == u.reply.Load() {
			return err
		}
		// A reply to the old transport may fail after migration has installed
		// a new one. Retry its still-owned data there instead of closing the
		// healthy UDP session because of an obsolete callback's error.
	}
}

func (u *SourceControl) bindReply(pkt *netapi.Packet) {
	previous := u.reply.Load()
	inboundID := pkt.InboundID()
	if inboundID == "" {
		inboundID = pkt.InboundName()
	}
	writer := pkt.ReplyWriter()
	if kind := reflect.TypeOf(writer); kind != nil && kind.Comparable() {
		// UOT streams expose a stable writer identity even when a multiplexed
		// connection gives all streams the same RemoteAddr.
		if previous.writer == writer && previous.inboundID == inboundID {
			return
		}
	} else if sameReplySource(previous.source, pkt.Src()) && previous.inboundID == inboundID {
		return
	}
	ctx, cancel := context.WithCancel(u.ctx)
	next := &replyBinding{inboundID: inboundID, writer: writer, source: pkt.Src(), write: pkt.WriteBackContext, ctx: ctx, cancel: cancel}
	u.reply.Store(next)
	previous.cancel()
}

// Exactly one writer belongs to the source, independently of socket readers.
// A late old reader cannot consume a replacement connection's notifications.
func (u *SourceControl) runReply() {
	defer close(u.replyDone)
	errorsInRow := 0
	var lastUndeliverableLog time.Time
	var lastConn *wrapConn
	for {
		select {
		case <-u.ctx.Done():
			return
		case <-u.notifyReceivedPacket:
			for {
				if u.ctx.Err() != nil {
					return
				}
				pkt, ok := u.receivedPackets.Pop()
				if !ok {
					break
				}
				// Rate limits are enforced before invoking the potentially blocking
				// inbound reply writer. Over-limit UDP packets are discarded;
				// they never wait in an additional unbounded queue.
				allowed := true
				if u.trafficControl != nil {
					routeID := ""
					if pkt.conn != nil {
						routeID = pkt.conn.routeID
					}
					allowed = u.trafficControl.Resolve(u.reply.Load().inboundID, routeID).AllowDatagram(trafficcontrol.Download, len(pkt.buf))
				}
				var err error
				if allowed {
					err = u.writeReply(u.ctx, pkt.buf, pkt.from)
				} else {
					metrics.Counter.AddReceiveUDPDroppedPacket()
				}
				u.queueBudget.ReleaseQueueBytes(int64(len(pkt.buf)))
				pool.PutBytes(pkt.buf)
				if !allowed {
					continue
				}
				if pkt.conn != lastConn {
					errorsInRow = 0
					lastConn = pkt.conn
				}
				if err == nil {
					errorsInRow = 0
					continue
				}
				if u.ctx.Err() != nil {
					return
				}
				if errors.Is(err, netapi.ErrUndeliverableDatagram) {
					// Malformed/oversized replies and output backpressure are
					// packet-local failures, not proof that the outbound socket
					// is broken. Avoid the consecutive transport error threshold.
					metrics.Counter.AddReceiveUDPDroppedPacket()
					if time.Since(lastUndeliverableLog) >= 30*time.Second {
						log.Warn("drop undeliverable UDP reply", "err", err)
						lastUndeliverableLog = time.Now()
					}
					continue
				}
				errorsInRow++
				if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) || errorsInRow > 13 {
					_ = pkt.conn.Close()
				} else {
					log.Error("write back failed", "err", err)
				}
			}
		}
	}
}
