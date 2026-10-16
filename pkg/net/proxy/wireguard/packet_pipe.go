package wireguard

import (
	"io"
	"net"
	"sync"
)

// packetPipe transfers borrowed packets synchronously. A writer may reuse its
// buffer only after the reader finishes copying, including during shutdown.
type packetPipe struct {
	mu      sync.Mutex
	packets chan []byte
	copied  chan struct{}
	done    <-chan struct{}
}

func newPacketPipe(done <-chan struct{}) packetPipe {
	return packetPipe{packets: make(chan []byte), copied: make(chan struct{}), done: done}
}

func (p *packetPipe) write(b []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case <-p.done:
		return net.ErrClosed
	case p.packets <- b:
		// Once accepted, Close must not release a buffer still used by read.
		<-p.copied
		return nil
	}
}

func (p *packetPipe) read(b []byte) (int, error) {
	select {
	case <-p.done:
		return 0, net.ErrClosed
	case packet := <-p.packets:
		var err error
		n := 0
		if len(packet) > len(b) {
			err = io.ErrShortBuffer
		} else {
			n = copy(b, packet)
		}
		p.copied <- struct{}{}
		return n, err
	}
}

type packetLink struct {
	fromEngine, toEngine packetPipe
	done                 chan struct{}
	once                 sync.Once
}

func newPacketLink() *packetLink {
	l := &packetLink{done: make(chan struct{})}
	l.fromEngine = newPacketPipe(l.done)
	l.toEngine = newPacketPipe(l.done)
	return l
}

func (l *packetLink) ReadPacket(b []byte) (int, error) { return l.fromEngine.read(b) }
func (l *packetLink) WritePacket(b []byte) error       { return l.toEngine.write(b) }
func (l *packetLink) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}
