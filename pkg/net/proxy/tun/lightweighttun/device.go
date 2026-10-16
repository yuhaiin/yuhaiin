// Package lightweighttun adapts the independent lightweight core to yuhaiin.
package lightweighttun

import (
	"errors"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"io"
)

type packetIO struct {
	device       netlink.Tun
	buffers      [][]byte
	sizes        []int
	count, next  int
	pendingErr   error
	writeBuffers [1][]byte
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
		if p.pendingErr != nil {
			err := p.pendingErr
			p.pendingErr = nil
			return 0, err
		}
		n, err := p.device.Read(p.buffers, p.sizes)
		if n == 0 && err != nil {
			return 0, err
		}
		if n < 1 || n > len(p.buffers) {
			return 0, io.ErrUnexpectedEOF
		}
		p.pendingErr = err
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
	if len(b) > 65575 {
		return io.ErrShortBuffer
	}
	offset := p.device.Offset()
	data := b
	if offset > 0 {
		data = pool.GetBytes(offset + len(b))
		defer pool.PutBytes(data)
		clear(data[:offset])
		copy(data[offset:], b)
	}
	// The stack has one writer. Native device writes borrow these buffers only
	// until return, so zero-offset TUNs need no additional copy or allocation.
	p.writeBuffers[0] = data
	n, err := p.device.Write(p.writeBuffers[:])
	p.writeBuffers[0] = nil
	// Native batch writers can report an accepted prefix plus an error. Our
	// one packet is complete when n==1; surfacing that trailing error would
	// make the stack retry an already accepted datagram.
	if n == 1 {
		return nil
	}
	if err != nil {
		return err
	}
	return io.ErrShortWrite
}
func (p *packetIO) Close() error { return p.device.Close() }
