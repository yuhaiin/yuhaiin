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
	mergeMap syncmap.SyncMap[uint64, *MergeFrag]
	SplitID  atomic.Uint64
	mu       sync.Mutex
}

type MergeFrag struct {
	time     time.Time
	Data     [][]byte
	Count    uint32
	Total    uint32
	TotalLen uint32
}

func (f *Frag) Merge(buf []byte) *pool.Buffer {
	fh := fragFrame(buf)

	if fh.Type() == FragmentTypeSingle {
		return pool.NewBUfferNoCopy(fh.Payload())
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

		buf := pool.NewBufferSize(atomic.LoadUint32(&mf.TotalLen))

		for _, v := range mf.Data {
			_, _ = buf.Write(v)
		}

		return buf
	}

	return nil
}

func (f *Frag) Split(buf []byte, maxSize int) [][]byte {
	headerSize := 1 + 8 + 1 + 1

	if maxSize <= headerSize {
		return nil
	}

	if len(buf) < maxSize-1 {
		return [][]byte{NewFragFrameBytesBuffer(FragmentTypeSingle, 0, 1, 0, buf)}
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

	var frameArray = make([][]byte, 0, frames)

	id := f.SplitID.Add(1)

	for i := range frames {
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
	conn                 *quic.Conn
	frag                 *Frag
}

func NewConnectionPacketConn(conn *quic.Conn) *ConnectionPacketConn {
	frag := &Frag{}

	var timer *time.Timer
	timer = time.AfterFunc(time.Minute, func() {
		select {
		case <-conn.Context().Done():
			return
		default:
			now := time.Now()
			for id, v := range frag.mergeMap.Range {
				if now.Sub(v.time) > 30*time.Second {
					frag.mergeMap.Delete(id)
				}
			}
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

	id := binary.BigEndian.Uint64(buf.Next(8))

	return id, buf, nil
}

func (c *ConnectionPacketConn) Write(b []byte, id uint64) error {
	buf := pool.GetBytes(8 + len(b))
	defer pool.PutBytes(buf)

	binary.BigEndian.PutUint64(buf, id)
	copy(buf[8:], b)

	return c.write(buf)
}

func (c *ConnectionPacketConn) write(buf []byte) error {
	maxSize := c.MaxDatagramFrameSize.Load()
	retry := false

_retry:
	buffers := c.frag.Split(buf, int(maxSize))
	defer func() {
		for _, v := range buffers {
			pool.PutBytes(v)
		}
	}()

	for _, v := range buffers {
		err := c.conn.SendDatagram(v)
		if err == nil {
			continue
		}

		te, ok := err.(*quic.DatagramTooLargeError)
		if !ok || retry {
			return err
		}

		c.MaxDatagramFrameSize.Store(te.MaxDatagramPayloadSize)
		maxSize = te.MaxDatagramPayloadSize
		retry = true
		goto _retry
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
func NewFragFrameBytesBuffer(t FragType, id uint64, total, current uint8, payload []byte) []byte {
	var buf []byte
	if t == FragmentTypeSingle {
		buf = pool.GetBytes(1 + len(payload))
	} else {
		buf = pool.GetBytes(1 + 8 + 1 + 1 + len(payload))
	}
	putFragFrame(buf, t, id, total, current, payload)
	return buf
}

func putFragFrame(buf []byte, t FragType, id uint64, total, current uint8, payload []byte) {
	buf[0] = byte(t)

	if t == FragmentTypeSingle {
		copy(buf[1:], payload)
		return
	}

	binary.BigEndian.PutUint64(buf[1:], id)
	buf[1+8] = total
	buf[1+8+1] = current
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
