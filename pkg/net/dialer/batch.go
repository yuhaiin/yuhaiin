package dialer

import (
	"io"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"golang.org/x/net/ipv6"
)

type BatchPacketConn struct {
	*net.UDPConn
	bc *ipv6.PacketConn

	messages []ipv6.Message
	i, n     int

	mu sync.RWMutex

	closed bool
}

func NewBatchPacketConn(pc *net.UDPConn) *BatchPacketConn {
	bc := &BatchPacketConn{
		UDPConn:  pc,
		bc:       ipv6.NewPacketConn(pc),
		messages: make([]ipv6.Message, configuration.UDPBatchSize),
	}

	for i := range bc.messages {
		bc.messages[i].Buffers = [][]byte{pool.GetBytes(pool.MaxSegmentSize)}
	}

	return bc
}

func (bc *BatchPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	if bc.i >= bc.n {
		if bc.closed {
			return 0, nil, io.EOF
		}

		n, err := bc.bc.ReadBatch(bc.messages, 0)
		if err != nil {
			return 0, nil, err
		}

		if n == 1 {
			bb := bc.messages[0]
			x := copy(b, bb.Buffers[0][:bb.N])
			return x, bb.Addr, nil
		}

		if n == 0 {
			return 0, nil, io.EOF
		}

		bc.i = 0
		bc.n = n
	}

	x := bc.messages[bc.i]
	bc.i++
	n := copy(b, x.Buffers[0][:x.N])

	return n, x.Addr, nil
}

func (bc *BatchPacketConn) Close() error {
	if bc.closed {
		return nil
	}

	err := bc.UDPConn.Close()

	bc.closed = true

	bc.mu.Lock()
	defer bc.mu.Unlock()

	messages := bc.messages
	bc.messages = nil

	for i := range messages {
		pool.PutBytes(messages[i].Buffers[0])
	}

	return err
}
