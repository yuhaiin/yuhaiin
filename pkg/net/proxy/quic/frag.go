package quic

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"github.com/quic-go/quic-go"
)

// https://github.com/quic-go/quic-go/blob/49e588a6a9905446e49d382d78115e6e960b1144/internal/protocol/params.go#L134
var MaxDatagramFrameSize int64 = 1200 - 3

type Frag struct {
	SplitID  atomic.Uint64
	mergeMap syncmap.SyncMap[uint64, *MergeFrag]

	timer *time.Timer
}

type MergeFrag struct {
	Count uint32
	Total uint32
	Data  [][]byte
	time  time.Time
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

func (f *Frag) Merge(buf []byte) []byte {
	fh := fragFrame(buf)

	if fh.Type() == FragmentTypeSingle {
		return buf[1:]
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
	mf.Data[index] = fh.Payload()

	if current == mf.Total {
		f.mergeMap.Delete(id)
		return bytes.Join(mf.Data, []byte{})
	}

	return nil
}

func (f *Frag) Split(buf []byte, maxSize int) [][]byte {
	if maxSize <= 12 {
		return nil
	}

	if len(buf) < maxSize-1 {
		return [][]byte{append([]byte{byte(FragmentTypeSingle)}, buf...)}
	}

	maxSize = maxSize - 8 - 2 - 2 - 1

	frames := len(buf) / maxSize
	if len(buf)%maxSize != 0 {
		frames++
	}

	var datas [][]byte = make([][]byte, 0, frames)

	id := f.SplitID.Add(1)

	for i := 0; i < frames; i++ {
		var frame []byte
		if i == frames-1 {
			frame = buf[i*maxSize:]
		} else {
			frame = buf[i*maxSize : (i+1)*maxSize]
		}

		datas = append(datas, NewFragFrame(FragmentTypeSplit, id, uint16(frames), uint16(i), frame))
	}

	return datas
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

func (c *ConnectionPacketConn) Receive(ctx context.Context) (uint64, []byte, error) {
_retry:
	data, err := c.conn.ReceiveDatagram(ctx)
	if err != nil {
		return 0, nil, err
	}

	buf := c.frag.Merge(data)
	if buf == nil {
		goto _retry
	}

	id := binary.BigEndian.Uint64(buf[:8])

	return id, buf[8:], nil
}

func (c *ConnectionPacketConn) Write(b []byte, id uint64) error {
	b = bytes.Join(
		[][]byte{
			binary.BigEndian.AppendUint64(make([]byte, 0, 8), id),
			b,
		},
		nil,
	)

	datas := c.frag.Split(b, int(MaxDatagramFrameSize))

	for _, v := range datas {
		if err := c.conn.SendDatagram(v); err != nil {
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

func NewFragFrame(t FragType, id uint64, total uint16, current uint16, payload []byte) fragFrame {
	buf := make([]byte, 1+8+2+2+len(payload))
	buf[0] = byte(t)
	binary.BigEndian.PutUint64(buf[1:], id)
	binary.BigEndian.PutUint16(buf[1+8:], total)
	binary.BigEndian.PutUint16(buf[1+8+2:], current)
	copy(buf[1+8+2+2:], payload)

	return buf
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

func (f fragFrame) Total() uint16 {
	if len(f) < 1+8+2 {
		return 0
	}

	return binary.BigEndian.Uint16(f[1+8:])
}

func (f fragFrame) Current() uint16 {
	if len(f) < 1+8+2+2 {
		return 0
	}

	return binary.BigEndian.Uint16(f[1+8+2:])
}

func (f fragFrame) Payload() []byte {
	return f[1+8+2+2:]
}

func (f fragFrame) SetType(t FragType) {
	f[0] = byte(t)
}

func (f fragFrame) SetID(id uint64) {
	binary.BigEndian.PutUint64(f[1:], id)
}

func (f fragFrame) SetTotal(total uint16) {
	binary.BigEndian.PutUint16(f[1+8:], total)
}

func (f fragFrame) SetCurrent(current uint16) {
	binary.BigEndian.PutUint16(f[1+8+2:], current)
}
