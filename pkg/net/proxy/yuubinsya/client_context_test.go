package yuubinsya

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// Like an HTTP/2 tunnel, the returned connection has its own lifetime and
// does not automatically close when the dialing context expires.
type handshakeProxy struct {
	netapi.Proxy
	conn net.Conn
}

func (p handshakeProxy) Conn(context.Context, netapi.Address) (net.Conn, error) {
	return p.conn, nil
}

func TestPacketHandshakeContext(t *testing.T) {
	for _, mode := range []string{"no_reply", "partial_reply", "blocked_write", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			local, remote := net.Pipe()
			t.Cleanup(func() { local.Close(); remote.Close() })
			c := &client{Proxy: handshakeProxy{conn: local}, hash: Salt(nil), overTCP: true}
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			ready := make(chan struct{})
			if mode != "blocked_write" {
				go func() {
					_, _ = io.CopyN(io.Discard, remote, 1+8+32)
					if mode == "partial_reply" {
						_, _ = remote.Write([]byte{1, 2, 3})
					}
					close(ready)
				}()
			} else {
				close(ready)
			}
			done := make(chan error, 1)
			go func() {
				pc, err := c.PacketConn(ctx, netapi.EmptyAddr)
				if pc != nil {
					pc.Close()
				}
				done <- err
			}()
			if mode == "cancel" {
				<-ready
				cancel()
			}
			select {
			case err := <-done:
				if !errors.Is(err, ctx.Err()) || err == nil {
					t.Fatalf("handshake error = %v, context error = %v", err, ctx.Err())
				}
			case <-time.After(time.Second):
				t.Fatal("handshake survived context cancellation")
			}
			if _, err := local.Write([]byte{1}); err == nil {
				t.Fatal("failed handshake left connection open")
			}
		})
	}
}

func TestPacketHandshakeSuccessDetachesContext(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	c := &client{Proxy: handshakeProxy{conn: local}, hash: Salt(nil), overTCP: true}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	go func() {
		_, _ = io.CopyN(io.Discard, remote, 1+8+32)
		var id [8]byte
		binary.BigEndian.PutUint64(id[:], 42)
		_, _ = remote.Write(id[:])
		_, _ = io.Copy(io.Discard, remote)
	}()
	pc, err := c.PacketConn(ctx, netapi.EmptyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	cancel()
	if err := pc.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := pc.WriteTo([]byte("still alive"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}); err != nil {
		t.Fatalf("successful connection tied to dialing context: %v", err)
	}
}

func TestStreamHeaderContext(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	c := &client{Proxy: handshakeProxy{conn: local}, hash: Salt(nil)}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := c.Conn(ctx, netapi.EmptyAddr); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked stream header survived context deadline")
	}
}
