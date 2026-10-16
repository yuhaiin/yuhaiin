// Package lightweighttun adapts the independent lightweight core to yuhaiin.
package lightweighttun

import (
	"errors"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"io"
)

type packetIO struct {
	device      netlink.Tun
	buffers     [][]byte
	sizes       []int
	count, next int
}

func newPacketIO(d netlink.Tun) (*packetIO, error) {
	if d.GSOEnabled() {
		return nil, errors.New("lightweight: offload device requires a validated segmentation adapter")
	}
	n := d.BatchSize()
	if n < 1 || n > 128 || d.Offset() < 0 || d.Offset() > 64 {
		return nil, errors.New("lightweight: invalid device batch/offset")
	}
	p := &packetIO{device: d, buffers: make([][]byte, n), sizes: make([]int, n)}
	for i := range p.buffers {
		p.buffers[i] = make([]byte, 65575+d.Offset())
	}
	return p, nil
}
func (p *packetIO) ReadPacket(b []byte) (int, error) {
	if p.next == p.count {
		n, err := p.device.Read(p.buffers, p.sizes)
		if err != nil {
			return 0, err
		}
		if n < 1 || n > len(p.buffers) {
			return 0, io.ErrUnexpectedEOF
		}
		p.count = n
		p.next = 0
	}
	i := p.next
	p.next++
	n := p.sizes[i]
	offset := p.device.Offset()
	if n < 1 || n > len(b) || n > len(p.buffers[i])-offset {
		return 0, io.ErrShortBuffer
	}
	return copy(b, p.buffers[i][offset:offset+n]), nil
}
func (p *packetIO) WritePacket(b []byte) error {
	data := make([]byte, p.device.Offset()+len(b))
	copy(data[p.device.Offset():], b)
	n, err := p.device.Write([][]byte{data})
	if err != nil {
		return err
	}
	if n != 1 {
		return io.ErrShortWrite
	}
	return nil
}
func (p *packetIO) Close() error { return p.device.Close() }
