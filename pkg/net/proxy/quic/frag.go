package quic

import (
	"context"
	"encoding/binary"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"github.com/quic-go/quic-go"
)

type Frag struct {
	SplitID  atomic.Uint64
	mu       sync.Mutex
	mergeMap syncmap.SyncMap[uint64, *MergeFrag]
}

type MergeFrag struct {
	Count    uint32
	Total    uint32
	TotalLen uint32
	Data     [][]byte
	time     time.Time
}

func (f *Frag) Merge(buf []byte) *pool.Buffer {
	fh := fragFrame(buf)

	if fh.Type() == FragmentTypeSingle {
		return pool.NewBuffer(fh.Payload())
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
		f.mu.Lock()

		mf, ok = f.mergeMap.Load(id)
		if !ok {
			mf, _ = f.mergeMap.LoadOrStore(id, &MergeFrag{
				Data:  make([][]byte, total),
				Total: uint32(total),
				time:  time.Now(),
			})
		}

		f.mu.Unlock()
	}

	mf.Data[index] = fh.Payload()
	atomic.AddUint32(&mf.TotalLen, uint32(len(fh.Payload())))

	if atomic.AddUint32(&mf.Count, 1) == mf.Total {
		f.mergeMap.Delete(id)

		buf := pool.GetBytesWriter(atomic.LoadUint32(&mf.TotalLen))

		for _, v := range mf.Data {
			_, _ = buf.Write(v)
		}

		return buf
	}

	return nil
}

func (f *Frag) Split(buf []byte, maxSize int) pool.MultipleBuffer {
	headerSize := 1 + 8 + 1 + 1

	if maxSize <= headerSize {
		return nil
	}

	if len(buf) < maxSize-1 {
		return pool.MultipleBuffer{NewFragFrameBytesBuffer(FragmentTypeSingle, 0, 1, 0, buf)}
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

	var frameArray pool.MultipleBuffer = make(pool.MultipleBuffer, 0, frames)

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
	MaxDatagramFrameSize *atomic.Int64
	conn                 quic.Connection
	frag                 *Frag
}

func NewConnectionPacketConn(conn quic.Connection) *ConnectionPacketConn {
	frag := &Frag{}

	var timer *time.Timer
	timer = time.AfterFunc(time.Minute, func() {
		select {
		case <-conn.Context().Done():
			return
		default:
			now := time.Now()
			frag.mergeMap.Range(func(id uint64, v *MergeFrag) bool {
				if now.Sub(v.time) > 30*time.Second {
					frag.mergeMap.Delete(id)
				}
				return true
			})
			timer.Reset(time.Minute)
		}
	})
	maxSize := &atomic.Int64{}
	maxSize.Store(1280)

	return &ConnectionPacketConn{conn: conn, frag: frag, MaxDatagramFrameSize: maxSize}
}

func (c *ConnectionPacketConn) Context() context.Context {
	return c.conn.Context()
}

func (c *ConnectionPacketConn) Receive(ctx context.Context) (uint64, *pool.Buffer, error) {
_retry:
	data, err := c.conn.ReceiveDatagram(ctx)
	if err != nil {
		return 0, nil, err
	}

	buf := c.frag.Merge(data)
	if buf == nil {
		goto _retry
	}

	id := binary.BigEndian.Uint64(buf.Discard(8))

	return id, buf, nil
}

func (c *ConnectionPacketConn) Write(b []byte, id uint64) error {
	buf := pool.GetBytesWriter(8 + len(b))

	buf.WriteUint64(id)
	_, _ = buf.Write(b)

	return c.write(buf, false)
}

func (c *ConnectionPacketConn) write(buf *pool.Buffer, retry bool) error {
	buffers := c.frag.Split(buf.Bytes(), int(c.MaxDatagramFrameSize.Load()))
	defer buffers.Free()

	for _, v := range buffers {
		err := c.conn.SendDatagram(v.Bytes())
		if err == nil {
			continue
		}

		te, ok := err.(*quic.DatagramTooLargeError)
		if !ok || retry {
			return err
		}

		c.MaxDatagramFrameSize.Store(te.MaxDatagramPayloadSize)

		buffers.Free()

		return c.write(buf, true)
	}

	return nil
}

type FragType uint8

const (
	FragmentTypeSplit FragType = iota + 1
	FragmentTypeSingle
)

type fragFrame []byte

/*
every frame max length: 1200 - 3

Single Frame
max payload length: 1200 - 3 - 1
+-------+~~~~~~~~~~~~~~+
| type  |    payload   |
+-------+~~~~~~~~~~~~~~+
|  1    |    variable  |
+-------+~~~~~~~~~~~~~~+

Split Frame
max payload length: 1200 - 3 - 1 - 8 - 1 - 1
+------+------------------+---------+---------+~~~~~~~~~~~~~~+
| type |        id        |  total  | current |    payload   |
+------+------------------+---------+---------+~~~~~~~~~~~~~~+
|  1   |      8 bytes     | 1 byte  | 1 byte  |    variable  |
+------+------------------+---------+---------+~~~~~~~~~~~~~~+
*/
func NewFragFrameBytesBuffer(t FragType, id uint64, total, current uint8, payload []byte) *pool.Buffer {
	var buf *pool.Buffer
	if t == FragmentTypeSingle {
		buf = pool.GetBytesWriter(1 + len(payload))
	} else {
		buf = pool.GetBytesWriter(1 + 8 + 1 + 1 + len(payload))
	}
	putFragFrame(buf, t, id, total, current, payload)
	return buf
}

func putFragFrame(buf *pool.Buffer, t FragType, id uint64, total, current uint8, payload []byte) {
	_ = buf.WriteByte(byte(t))

	if t == FragmentTypeSingle {
		_, _ = buf.Write(payload)
		return
	}

	buf.WriteUint64(id)
	_ = buf.WriteByte(total)
	_ = buf.WriteByte(current)
	_, _ = buf.Write(payload)
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
