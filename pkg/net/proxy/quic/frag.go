package quic

import (
	"context"
	"encoding/binary"
	"math"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"github.com/quic-go/quic-go"
)

// https://github.com/quic-go/quic-go/blob/49e588a6a9905446e49d382d78115e6e960b1144/internal/protocol/params.go#L134
var MaxDatagramFrameSize int64 = 1200

type Frag struct {
	SplitID  atomic.Uint64
	mergeMap syncmap.SyncMap[uint64, *MergeFrag]

	timer *time.Timer
}

type MergeFrag struct {
	Count    uint32
	Total    uint32
	TotalLen uint32
	Data     [][]byte
	time     time.Time
}

func (f *Frag) close() {
	if f.timer != nil {
		f.timer.Stop()
	}
}

func (f *Frag) collect(ctx context.Context) {
	if f.timer == nil {
		f.timer = time.NewTimer(60 * time.Second)
	}

	for {
		select {
		case <-ctx.Done():
			f.close()
			return

		case <-f.timer.C:
			now := time.Now()
			f.mergeMap.Range(func(id uint64, v *MergeFrag) bool {
				if now.Sub(v.time) > 30*time.Second {
					f.mergeMap.Delete(id)
				}
				return true
			})
		}
	}
}

func (f *Frag) Merge(buf []byte) *pool.Bytes {
	fh := fragFrame(buf)

	if fh.Type() == FragmentTypeSingle {
		return pool.NewBytesBuffer(fh.Payload())
	}

	total := fh.Total()
	index := fh.Current()
	id := fh.ID()

	mf, ok := f.mergeMap.Load(id)

	if fh.Type() != FragmentTypeSplit || total == 0 || index >= total || (ok && uint32(total) != mf.Total) {
		f.mergeMap.Delete(id)
		return nil
	}

	if !ok {
		mf, _ = f.mergeMap.LoadOrStore(id, &MergeFrag{
			Data:  make([][]byte, total),
			Total: uint32(total),
			time:  time.Now(),
		})
	}

	current := atomic.AddUint32(&mf.Count, 1)
	atomic.AddUint32(&mf.TotalLen, uint32(len(fh.Payload())))
	mf.Data[index] = fh.Payload()

	if current == mf.Total {
		f.mergeMap.Delete(id)

		buf := pool.GetBytesBuffer(mf.TotalLen)

		offset := 0
		for _, v := range mf.Data {
			offset += copy(buf.Bytes()[offset:], v)
		}
		return buf
	}

	return nil
}

func (f *Frag) Split(buf []byte, maxSize int) pool.MultipleBytes {
	headerSize := 1 + 8 + 1 + 1

	if maxSize <= headerSize {
		return nil
	}

	if len(buf) < maxSize-1 {
		b := pool.GetBytesBuffer(1 + len(buf))
		b.Bytes()[0] = byte(FragmentTypeSingle)
		copy(b.Bytes()[1:], buf)
		return pool.MultipleBytes{b}
	}

	maxSize = maxSize - headerSize

	frames := len(buf) / maxSize
	if len(buf)%maxSize != 0 {
		frames++
	}

	if frames > math.MaxUint8 {
		log.Error("too many frames", "frames", frames)
		return nil
	}

	var frameArray pool.MultipleBytes = make(pool.MultipleBytes, 0, frames)

	id := f.SplitID.Add(1)

	for i := 0; i < frames; i++ {
		var frame []byte
		if i == frames-1 {
			frame = buf[i*maxSize:]
		} else {
			frame = buf[i*maxSize : (i+1)*maxSize]
		}

		frameArray = append(frameArray, NewFragFrameBytesBuffer(FragmentTypeSplit, id, uint8(frames), uint8(i), frame))
	}

	return frameArray
}

type ConnectionPacketConn struct {
	conn quic.Connection
	frag *Frag
}

func NewConnectionPacketConn(conn quic.Connection) *ConnectionPacketConn {
	frag := &Frag{}
	go frag.collect(conn.Context())
	return &ConnectionPacketConn{conn: conn, frag: frag}
}

func (c *ConnectionPacketConn) Context() context.Context {
	return c.conn.Context()
}

func (c *ConnectionPacketConn) Receive(ctx context.Context) (uint64, *pool.Bytes, error) {
_retry:
	data, err := c.conn.ReceiveDatagram(ctx)
	if err != nil {
		return 0, nil, err
	}

	buf := c.frag.Merge(data)
	if buf == nil {
		goto _retry
	}

	id := binary.BigEndian.Uint64(buf.Bytes()[:8])

	buf.ResetSize(8, buf.Len())

	return id, buf, nil
}

func (c *ConnectionPacketConn) Write(b []byte, id uint64) error {
	buf := pool.GetBytesBuffer(8 + len(b))

	binary.BigEndian.PutUint64(buf.Bytes()[:8], id)
	copy(buf.Bytes()[8:], b)

	buffers := c.frag.Split(buf.Bytes(), int(MaxDatagramFrameSize))
	defer buffers.Drop()

	for _, v := range buffers {
		if err := c.conn.SendDatagram(v.Bytes()); err != nil {
			return err
		}
	}

	return nil
}

type FragType uint8

const (
	FragmentTypeSplit FragType = iota + 1
	FragmentTypeSingle
)

type fragFrame []byte

func NewFragFrame(t FragType, id uint64, total, current uint8, payload []byte) fragFrame {
	buf := make([]byte, 1+8+1+1+len(payload))
	putFragFrame(buf, t, id, total, current, payload)
	return buf
}

func NewFragFrameBytesBuffer(t FragType, id uint64, total, current uint8, payload []byte) *pool.Bytes {
	buf := pool.GetBytesBuffer(1 + 8 + 1 + 1 + len(payload))
	putFragFrame(buf.Bytes(), t, id, total, current, payload)
	return buf
}

func putFragFrame(buf []byte, t FragType, id uint64, total, current uint8, payload []byte) {
	buf[0] = byte(t)
	binary.BigEndian.PutUint64(buf[1:], id)
	buf[1+8+1-1] = total
	buf[1+8+1+1-1] = current
	copy(buf[1+8+1+1:], payload)
}

func (f fragFrame) Type() FragType {
	if len(f) < 1 {
		return 0
	}

	return FragType(f[0])
}

func (f fragFrame) ID() uint64 {
	if len(f) < 1+8 {
		return 0
	}

	return binary.BigEndian.Uint64(f[1:])
}

func (f fragFrame) Total() uint8 {
	if len(f) < 1+8+1 {
		return 0
	}

	return f[1+8+1-1]
}

func (f fragFrame) Current() uint8 {
	if len(f) < 1+8+1+1 {
		return 0
	}

	return f[1+8+1+1-1]
}

func (f fragFrame) Payload() []byte {
	if f.Type() == FragmentTypeSingle {
		return f[1:]
	}

	if len(f) < 1+8+1+1 {
		return nil
	}

	return f[1+8+1+1:]
}
