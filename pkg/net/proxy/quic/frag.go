package quic

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"
)

// https://github.com/quic-go/quic-go/blob/49e588a6a9905446e49d382d78115e6e960b1144/internal/protocol/params.go#L134
var MaxDatagramFrameSize int64 = 1200 - 3

type Frag struct {
	SplitID atomic.Uint64

	mu       sync.Mutex
	mergeMap map[uint64]*MergeFrag
}

type FragData struct {
	PacketID uint64
	Total    uint16
	Current  uint16
}

type MergeFrag struct {
	Count uint16
	Data  [][]byte
}

func (f *Frag) Merge(buf []byte) []byte {
	bb := bytes.NewBuffer(buf)
	frag := FragData{}
	binary.Read(bb, binary.BigEndian, &frag) //nolint:errcheck

	f.mu.Lock()
	defer f.mu.Unlock()

	if f.mergeMap == nil {
		f.mergeMap = make(map[uint64]*MergeFrag)
	}

	mf, ok := f.mergeMap[frag.PacketID]
	if !ok {
		mf = &MergeFrag{
			Data: make([][]byte, frag.Total),
		}
		f.mergeMap[frag.PacketID] = mf
	}

	mf.Count++
	mf.Data[frag.Current] = bb.Bytes()

	if mf.Count == frag.Total {
		delete(f.mergeMap, frag.PacketID)
		return bytes.Join(mf.Data, []byte{})
	}

	return nil
}

func (f *Frag) Split(buf []byte, maxSize int) [][]byte {
	if maxSize <= 12 {
		return nil
	}

	id := f.SplitID.Add(1)

	maxSize = maxSize - 8 - 2 - 2

	frames := len(buf) / maxSize
	if len(buf)%maxSize != 0 {
		frames++
	}

	var datas [][]byte

	for i := 0; i < frames; i++ {
		var frame []byte
		if i == frames-1 {
			frame = buf[i*maxSize:]
		} else {
			frame = buf[i*maxSize : (i+1)*maxSize]
		}

		f := FragData{
			PacketID: id,
			Total:    uint16(frames),
			Current:  uint16(i),
		}

		buf := bytes.NewBuffer(nil)
		binary.Write(buf, binary.BigEndian, f) //nolint:errcheck
		buf.Write(frame)

		datas = append(datas, buf.Bytes())
	}

	return datas
}

type ConnectionPacketConn struct {
	ctx  context.Context
	conn quic.Connection
	frag Frag
}

func NewConnectionPacketConn(ctx context.Context, conn quic.Connection) *ConnectionPacketConn {
	return &ConnectionPacketConn{ctx: ctx, conn: conn, frag: Frag{}}
}

func (c *ConnectionPacketConn) Receive() (uint64, []byte, error) {
_retry:
	data, err := c.conn.ReceiveDatagram(c.ctx)
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
	b = append(binary.BigEndian.AppendUint64(nil, id), b...)

	datas := c.frag.Split(b, int(MaxDatagramFrameSize))

	for _, v := range datas {
		if err := c.conn.SendDatagram(v); err != nil {
			return err
		}
	}

	return nil
}
