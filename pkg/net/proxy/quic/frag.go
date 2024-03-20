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
// the minium depend on DataLenPresent, the minium need minus 3
// see: https://github.com/quic-go/quic-go/blob/1e874896cd39adc02663be4d77ade701b333df5a/internal/wire/datagram_frame.go#L62
var MaxDatagramFrameSize int64 = 1200 - 3

type Frag struct {
	SplitID  atomic.Uint64
	mergeMap syncmap.SyncMap[uint64, *MergeFrag]
}

type MergeFrag struct {
	Count    uint32
	Total    uint32
	TotalLen uint32
	Data     [][]byte
	time     time.Time
}

func (f *Frag) collect(ctx context.Context) {
	timer := time.NewTimer(60 * time.Second)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-timer.C:
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

		buf := pool.GetBytesWriter(mf.TotalLen)
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
	defer buf.Free()

	buf.WriteUint64(id)
	_, _ = buf.Write(b)

	buffers := c.frag.Split(buf.Bytes(), int(MaxDatagramFrameSize))
	defer buffers.Free()

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
	buf.WriteByte(byte(t))

	if t == FragmentTypeSingle {
		buf.Write(payload)
		return
	}

	buf.WriteUint64(id)
	buf.WriteByte(total)
	buf.WriteByte(current)
	buf.Write(payload)
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
