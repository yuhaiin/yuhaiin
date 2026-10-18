package masque

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/masque/connectip"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type observeHeaderWrite struct {
	net.Conn
	writes  atomic.Int32
	started chan struct{}
}

// A real TCP peer exercises HPACK, SETTINGS, DATA and both flow-control windows.
// It deliberately advertises a 1024-byte stream window so every packet stalls
// for WINDOW_UPDATE at least once. TLS and Cloudflare authentication are absent.
func newHTTP2EchoTunnel(t testing.TB) *connectip.Conn {
	t.Helper()
	lis, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(conn, preface); err != nil {
			return
		}
		fr := http2.NewFramer(conn, conn)
		fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
		if err := fr.WriteSettings(http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1}, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1024}); err != nil {
			return
		}
		for {
			frame, err := fr.ReadFrame()
			if err != nil {
				return
			}
			switch f := frame.(type) {
			case *http2.SettingsFrame:
				if !f.IsAck() {
					if err := fr.WriteSettingsAck(); err != nil {
						return
					}
				}
			case *http2.MetaHeadersFrame:
				if f.PseudoValue("protocol") != "connect-ip" {
					return
				}
				var block bytes.Buffer
				enc := hpack.NewEncoder(&block)
				if err := enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"}); err != nil {
					return
				}
				if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: f.StreamID, BlockFragment: block.Bytes(), EndHeaders: true}); err != nil {
					return
				}
			case *http2.DataFrame:
				if f.StreamEnded() {
					return
				}
				if f.Length > 0 {
					if err := fr.WriteWindowUpdate(0, f.Length); err != nil {
						return
					}
					if err := fr.WriteWindowUpdate(f.StreamID, f.Length); err != nil {
						return
					}
					if err := fr.WriteData(f.StreamID, false, f.Data()); err != nil {
						return
					}
				}
			}
		}
	}()
	tcp, err := net.Dial("tcp4", lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c, err := newHTTP2ClientConn(tcp, 0)
	if err != nil {
		_ = tcp.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(); <-done })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	req, err := connectip.NewRequest(ctx, "https://proxy.example/")
	if err != nil {
		t.Fatal(err)
	}
	tunnel, _, err := connectip.NewHTTP2ClientConn(c).Dial(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tunnel.Close() })
	if err := tunnel.AdvertiseRoute([]connectip.IPRoute{{StartIP: netip.IPv4Unspecified(), EndIP: netip.MustParseAddr("255.255.255.255")}}); err != nil {
		t.Fatal(err)
	}
	return tunnel
}

func echoTunnelPacket() []byte {
	b := make([]byte, 1200)
	b[0], b[8], b[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	copy(b[12:16], []byte{192, 0, 2, 1})
	copy(b[16:20], []byte{192, 0, 2, 2})
	return b
}

func TestHTTP2CapsuleTunnelFlowControl(t *testing.T) {
	tunnel := newHTTP2EchoTunnel(t)
	packet, received := echoTunnelPacket(), make([]byte, 1500)
	// Exceeds the 6 MiB stream receive window as well as the initial send
	// window, so neither missing window updates nor capsule splitting can hide.
	for range 6000 {
		packet[8] = 64
		if _, err := tunnel.WritePacket(packet); err != nil {
			t.Fatal(err)
		}
		n, err := tunnel.ReadPacket(received)
		if err != nil || !bytes.Equal(received[:n], packet) {
			t.Fatalf("echo bytes=%d: %v", n, err)
		}
	}
}

func BenchmarkHTTP2CapsuleTunnel(b *testing.B) {
	tunnel := newHTTP2EchoTunnel(b)
	packet, received := echoTunnelPacket(), make([]byte, 1500)
	b.SetBytes(int64(len(packet)))
	b.ReportAllocs()
	for b.Loop() {
		packet[8] = 64
		if _, err := tunnel.WritePacket(packet); err != nil {
			b.Fatal(err)
		}
		n, err := tunnel.ReadPacket(received)
		if err != nil || !bytes.Equal(received[:n], packet) {
			b.Fatalf("echo bytes=%d: %v", n, err)
		}
	}
}

func (c *observeHeaderWrite) Write(p []byte) (int, error) {
	if c.writes.Add(1) == 2 {
		close(c.started)
	}
	return c.Conn.Write(p)
}

func TestHTTP2RejectsSendWindowOverflow(t *testing.T) {
	for _, stream := range []uint32{0, http2StreamID} {
		var data bytes.Buffer
		writer := http2.NewFramer(&data, nil)
		if err := writer.WriteWindowUpdate(stream, 1); err != nil {
			t.Fatal(err)
		}
		frame, err := http2.NewFramer(nil, &data).ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		c := &http2ClientConn{connSendWindow: 1<<31 - 1, streamSendWindow: 1<<31 - 1}
		c.cond.L = &c.mu
		if err := c.handleFrame(frame); err == nil {
			t.Fatalf("accepted overflowing send window on stream %d", stream)
		}
	}
}

func TestHTTP2CancelBlockedHeaders(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	ready := make(chan struct{})
	go func() {
		// Drain the preface and initial settings only; then block all writes.
		preface := make([]byte, len(http2.ClientPreface))
		_, _ = io.ReadFull(b, preface)
		fr := http2.NewFramer(io.Discard, b)
		_, _ = fr.ReadFrame()
		_, _ = fr.ReadFrame()
		close(ready)
	}()
	observed := &observeHeaderWrite{Conn: a, started: make(chan struct{})}
	c, err := newHTTP2ClientConn(observed, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	<-ready
	c.mu.Lock()
	c.gotSettings, c.extendedConnect = true, true
	close(c.settings)
	c.mu.Unlock()
	ctx, cancel := context.WithCancel(t.Context())
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://proxy.example/", nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := c.RoundTrip(req); done <- err }()
	<-observed.started
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled request succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt blocked HEADERS write")
	}
	if err := c.connErr(); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
