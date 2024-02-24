package tun

import (
	"io"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	wun "golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ writer = (*wgWriter)(nil)

type wgWriter struct {
	file io.ReadWriteCloser
}

func (w *wgWriter) Write(b []byte) tcpip.Error {
	_, err := w.file.Write(b)
	if err == nil {
		return nil
	}

	log.Error("write packet failed", "err", err)
	return &tcpip.ErrClosedForSend{}
}

func (w *wgWriter) WritePacket(pkt stack.PacketBufferPtr) tcpip.Error {
	buf := pkt.ToBuffer()
	defer buf.Release()

	if offset > 0 {
		v := buffer.NewViewWithData(make([]byte, offset))
		_ = buf.Prepend(v)
	}

	if err := w.Write(buf.Flatten()); err != nil {
		return &tcpip.ErrInvalidEndpointState{}
	}
	return nil
}

func (w *wgWriter) Close() error { return w.file.Close() }

func (w *wgWriter) dispatch(e stack.NetworkDispatcher, mtu uint32) (bool, tcpip.Error) {
	buf := pool.GetBytes(mtu + uint32(offset))
	defer pool.PutBytes(buf)

	n, err := w.file.Read(buf)
	if err != nil {
		log.Error("receive packet failed", "err", err)
		return false, &tcpip.ErrAborted{}
	}

	if n == 0 || n > int(mtu) {
		return true, nil
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(buf[offset : n+offset]),
	})
	defer pkt.DecRef()

	var p tcpip.NetworkProtocolNumber

	switch header.IPVersion(buf[offset:]) {
	case header.IPv4Version:
		p = header.IPv4ProtocolNumber
	case header.IPv6Version:
		p = header.IPv6ProtocolNumber
	default:
		return true, nil
	}

	e.DeliverNetworkPacket(p, pkt)
	return true, nil
}

type wgTun struct {
	offset int
	nt     wun.Device
}

func newWgTun(device wun.Device) *wgTun {
	return &wgTun{
		offset: offset,
		nt:     device,
	}
}

var (
	bufferPool = sync.Pool{New: func() any { return make([][]byte, 1) }}
	sizePool   = sync.Pool{New: func() any { return make([]int, 1) }}
)

func getBuffer(b []byte) [][]byte {
	buf := bufferPool.Get().([][]byte)
	buf[0] = b

	return buf
}

func putBuffer(buffs [][]byte) {
	buffs[0] = nil
	bufferPool.Put(buffs)
}

func getSize() []int { return sizePool.Get().([]int) }

func (t *wgTun) Read(packet []byte) (int, error) {
	size := getSize()
	defer sizePool.Put(size)
	buffs := getBuffer(packet)
	defer putBuffer(buffs)

	_, err := t.nt.Read(buffs, size, t.offset)
	return size[0], err
}

func (t *wgTun) Write(packet []byte) (int, error) {
	buffs := getBuffer(packet)
	defer putBuffer(buffs)

	return t.nt.Write(buffs, t.offset)
}

func (t *wgTun) Close() error       { return t.nt.Close() }
func (t *wgTun) Device() wun.Device { return t.nt }
