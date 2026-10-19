package nat

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
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
	writer := pkt.ReplyWriter()
	if kind := reflect.TypeOf(writer); kind != nil && kind.Comparable() {
		// UOT streams expose a stable writer identity even when a multiplexed
		// connection gives all streams the same RemoteAddr.
		if previous.writer == writer {
			return
		}
	} else if sameReplySource(previous.source, pkt.Src()) {
		return
	}
	ctx, cancel := context.WithCancel(u.ctx)
	next := &replyBinding{writer: writer, source: pkt.Src(), write: pkt.WriteBackContext, ctx: ctx, cancel: cancel}
	u.reply.Store(next)
	previous.cancel()
}

// Exactly one writer belongs to the source, independently of socket readers.
// A late old reader cannot consume a replacement connection's notifications.
func (u *SourceControl) runReply() {
	defer close(u.replyDone)
	errorsInRow := 0
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
				err := u.writeReply(u.ctx, pkt.buf, pkt.from)
				u.queueBudget.ReleaseQueueBytes(int64(len(pkt.buf)))
				pool.PutBytes(pkt.buf)
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
