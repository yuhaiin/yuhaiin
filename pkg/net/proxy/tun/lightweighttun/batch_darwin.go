//go:build darwin && !ios

package lightweighttun

import (
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight"
	"io"
)

func platformPacketIO(p *packetIO) lightweight.PacketIO {
	if d, ok := p.device.(interface{ ExperimentalUTUNBatchSize() int }); ok {
		return &utunPacketIO{packetIO: p, batch: d.ExperimentalUTUNBatchSize()}
	}
	return p
}

type utunPacketIO struct {
	*packetIO
	batch int
	bufs  [128][]byte
}

func (p *utunPacketIO) PacketBatchSize() int { return p.batch }
func (p *utunPacketIO) WritePacketBatch(packets []lightweight.PacketBuffer) (int, error) {
	if len(packets) > len(p.bufs) {
		return 0, io.ErrShortBuffer
	}
	for i, packet := range packets {
		if packet.Offset < p.device.Offset() || packet.Offset > len(packet.Data) || packet.SegmentSize != 0 {
			clear(p.bufs[:i])
			return 0, io.ErrShortBuffer
		}
		p.bufs[i] = packet.Data[packet.Offset-p.device.Offset():]
	}
	n, err := p.device.Write(p.bufs[:len(packets)])
	clear(p.bufs[:len(packets)])
	return n, err
}
