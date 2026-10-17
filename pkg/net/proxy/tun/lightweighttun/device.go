// Package lightweighttun adapts the independent lightweight core to yuhaiin.
package lightweighttun

import (
	"errors"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight"
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
	viewReader   lightweight.PacketViewReader
	writer       devicePacketWriter
}

type devicePacketWriter interface {
	MaxGSOPacketSize() int
	WritePacketBuffer([]byte, int, int) error
}

// NewPacketIO adapts a native TUN to the independent packet stack. The returned
// adapter owns the device; on error ownership remains with the caller.
func NewPacketIO(d netlink.Tun) (lightweight.PacketIO, error) {
	p, err := newPacketIO(d)
	if err != nil {
		return nil, err
	}
	return platformPacketIO(p), nil
}

func newPacketIO(d netlink.Tun) (*packetIO, error) {
	writer, offloadAware := d.(devicePacketWriter)
	if d.GSOEnabled() && !offloadAware {
		return nil, errors.New("lightweight: offload device requires a validated segmentation adapter")
	}
	n := d.BatchSize()
	if n < 1 || n > 128 || d.Offset() < 0 || d.Offset() > 64 {
		return nil, errors.New("lightweight: invalid device batch/offset")
	}
	p := &packetIO{device: d, buffers: make([][]byte, n), sizes: make([]int, n)}
	if offloadAware {
		p.writer = writer
	}
	if reader, ok := d.(lightweight.PacketViewReader); ok && n == 1 {
		p.viewReader = reader
	} else {
		for i := range p.buffers {
			p.buffers[i] = make([]byte, 65575+d.Offset())
		}
	}
	return p, nil
}
func (p *packetIO) ReadPacket(b []byte) (int, error) {
	// The complete-packet API must not discard partial-checksum metadata from
	// a trusted view. Native Read finishes such checksums for legacy callers.
	data, _, err := p.readDevicePacketView()
	if len(data) > len(b) {
		return 0, io.ErrShortBuffer
	}
	return copy(b, data), err
}
func (p *packetIO) ReadPacketView() ([]byte, bool, error) {
	if p.viewReader != nil {
		return p.viewReader.ReadPacketView()
	}
	return p.readDevicePacketView()
}
func (p *packetIO) readDevicePacketView() ([]byte, bool, error) {
	if p.buffers[0] == nil {
		for i := range p.buffers {
			p.buffers[i] = make([]byte, 65575+p.device.Offset())
		}
	}
	if p.next == p.count {
		if p.pendingErr != nil {
			err := p.pendingErr
			p.pendingErr = nil
			return nil, false, err
		}
		n, err := p.device.Read(p.buffers, p.sizes)
		if n == 0 && err != nil {
			return nil, false, err
		}
		if n < 1 || n > len(p.buffers) {
			return nil, false, io.ErrUnexpectedEOF
		}
		p.pendingErr = err
		p.count = n
		p.next = 0
	}
	i := p.next
	p.next++
	n := p.sizes[i]
	offset := p.device.Offset()
	if n < 1 || n > len(p.buffers[i])-offset {
		return nil, false, io.ErrShortBuffer
	}
	return p.buffers[i][offset : offset+n], false, nil
}

func (p *packetIO) Headroom() int { return p.device.Offset() }
func (p *packetIO) MaxGSOPacketSize() int {
	if p.writer != nil {
		return p.writer.MaxGSOPacketSize()
	}
	return 0
}

func (p *packetIO) WritePacketBuffer(b []byte, offset, segmentSize int) error {
	if offset < 0 || offset > len(b) {
		return io.ErrShortBuffer
	}
	if offset < p.device.Offset() {
		if segmentSize != 0 {
			return io.ErrShortBuffer
		}
		return p.WritePacket(b[offset:])
	}
	if p.writer != nil {
		return p.writer.WritePacketBuffer(b, offset, segmentSize)
	}
	if segmentSize != 0 {
		return errors.New("lightweight: packet device does not support GSO")
	}
	return p.write(b[offset-p.device.Offset():])
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
	return p.write(data)
}
func (p *packetIO) write(data []byte) error {
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
