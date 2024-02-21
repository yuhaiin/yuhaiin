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
	// defer pkt.DecRef()

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
	rMutex sync.Mutex
	wMutex sync.Mutex
	rSizes []int
	rBuffs [][]byte
	wBuffs [][]byte
	offset int

	nt wun.Device
}

func newWgTun(device wun.Device) *wgTun {
	return &wgTun{
		offset: offset,
		rSizes: make([]int, 1),
		rBuffs: make([][]byte, 1),
		wBuffs: make([][]byte, 1),
		nt:     device,
	}
}

func (t *wgTun) Read(packet []byte) (int, error) {
	t.rMutex.Lock()
	defer t.rMutex.Unlock()
	t.rBuffs[0] = packet
	_, err := t.nt.Read(t.rBuffs, t.rSizes, t.offset)
	return t.rSizes[0], err
}

func (t *wgTun) Write(packet []byte) (int, error) {
	t.wMutex.Lock()
	defer t.wMutex.Unlock()
	t.wBuffs[0] = packet
	return t.nt.Write(t.wBuffs, t.offset)
}

func (t *wgTun) Close() error {
	return t.nt.Close()
}
