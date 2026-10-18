package connectip

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/apernet/quic-go"
)

type blockedDatagramStream struct {
	net.Conn
	receiving chan struct{}
}

func (s *blockedDatagramStream) CancelRead(quic.StreamErrorCode)  { _ = s.Close() }
func (s *blockedDatagramStream) CancelWrite(quic.StreamErrorCode) { _ = s.Close() }
func (*blockedDatagramStream) StreamID() quic.StreamID            { return 0 }
func (*blockedDatagramStream) SendDatagram([]byte) error          { return nil }
func (s *blockedDatagramStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	close(s.receiving)
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestCloseUnblocksDatagramReader(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	s := &blockedDatagramStream{Conn: a, receiving: make(chan struct{})}
	c := newProxiedConn(s)
	t.Cleanup(func() { _ = c.Close() })
	done := make(chan error, 1)
	go func() { _, err := c.ReadPacket(make([]byte, 1500)); done <- err }()
	<-s.receiving
	if err := c.Close(); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("ReadPacket: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close left ReceiveDatagram blocked")
	}
}
