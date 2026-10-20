package trafficcontrol

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestWrappedStreamPacesBothDirectionsAndSeesLiveCaps(t *testing.T) {
	m := NewManager()
	policy := m.Resolve("client", "")
	for _, direction := range []Direction{Upload, Download} {
		t.Run(map[Direction]string{Upload: "upload", Download: "download"}[direction], func(t *testing.T) {
			client, peer := net.Pipe()
			defer peer.Close()
			c := WrapConn(t.Context(), client, func() Policy { return policy })
			defer c.Close()
			spec := Profile{}
			rate := Rate{BytesPerSecond: 32768, BurstBytes: 1024}
			if direction == Upload {
				spec.Upload = rate
			} else {
				spec.Download = rate
			}
			if err := m.Apply(Config{Enabled: true, Global: spec}); err != nil {
				t.Fatal(err)
			}
			data := bytes.Repeat([]byte{0x42}, 8192)
			done := make(chan error, 1)
			started := time.Now()
			if direction == Upload {
				go func() { _, err := peer.Write(data); done <- err }()
				got := make([]byte, len(data))
				if _, err := io.ReadFull(c, got); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, data) {
					t.Fatal("upload payload corrupted")
				}
			} else {
				go func() { _, err := c.Write(data); done <- err }()
				got := make([]byte, len(data))
				if _, err := io.ReadFull(peer, got); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, data) {
					t.Fatal("download payload corrupted")
				}
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if elapsed := time.Since(started); elapsed < 180*time.Millisecond {
				t.Fatalf("rate bypass: %v", elapsed)
			}
		})
	}
}

func TestWrappedStreamCancellationInterruptsPacing(t *testing.T) {
	m := NewManager()
	if err := m.Apply(Config{Enabled: true, Global: Profile{Download: Rate{BytesPerSecond: 1, BurstBytes: 1}}}); err != nil {
		t.Fatal(err)
	}
	raw, peer := net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithCancel(t.Context())
	c := WrapConn(ctx, raw, func() Policy { return m.Resolve("", "") })
	defer c.Close()
	done := make(chan error, 1)
	go func() { _, err := c.Write([]byte("wait")); done <- err }()
	first := make([]byte, 1)
	if _, err := io.ReadFull(peer, first); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled write succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("pacing ignored cancellation")
	}
}

func TestWrappedReadDeadlineCanResumeWithoutLosingPayload(t *testing.T) {
	m := NewManager()
	if err := m.Apply(Config{Enabled: true, Global: Profile{Upload: Rate{BytesPerSecond: 1, BurstBytes: 1}}}); err != nil {
		t.Fatal(err)
	}
	raw, peer := net.Pipe()
	defer peer.Close()
	c := WrapConn(t.Context(), raw, func() Policy { return m.Resolve("", "") })
	defer c.Close()
	data := []byte("preserve every byte after a read timeout")
	sent := make(chan error, 1)
	go func() { _, err := peer.Write(data); sent <- err }()
	if err := c.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(data))
	n, err := c.Read(buf)
	if !errors.Is(err, os.ErrDeadlineExceeded) || n != 1 {
		t.Fatalf("paced read ignored deadline: n=%d err=%v", n, err)
	}
	if err := m.Apply(Config{}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, buf[n:]); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, data) {
		t.Fatalf("read timeout lost payload: %q", buf)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
}

func TestChangingWriteDeadlineInterruptsPacing(t *testing.T) {
	m := NewManager()
	if err := m.Apply(Config{Enabled: true, Global: Profile{Download: Rate{BytesPerSecond: 1, BurstBytes: 1}}}); err != nil {
		t.Fatal(err)
	}
	raw, peer := net.Pipe()
	defer peer.Close()
	c := WrapConn(t.Context(), raw, func() Policy { return m.Resolve("", "") })
	defer c.Close()
	done := make(chan error, 1)
	go func() { _, err := c.Write([]byte("paced")); done <- err }()
	if _, err := io.ReadFull(peer, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if err := c.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("unexpected write deadline error: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("pacing did not observe the changed deadline")
	}
}

func TestWrappedTCPHalfClosePreservesResponse(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	raw, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	peer, err := listener.AcceptTCP()
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	defer peer.Close()
	m := NewManager()
	if err := m.Apply(Config{Enabled: true, Global: Profile{
		Upload: Rate{BytesPerSecond: 1 << 20}, Download: Rate{BytesPerSecond: 1 << 20},
	}}); err != nil {
		t.Fatal(err)
	}
	c := WrapConn(t.Context(), raw, func() Policy { return m.Resolve("", "") })
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	request, err := io.ReadAll(peer)
	if err != nil || string(request) != "request" {
		t.Fatalf("request=%q err=%v", request, err)
	}
	if _, err := peer.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err := peer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	// Exercise the buffer-lending adapter as well as ordinary half-close.
	reader := c.(interface {
		ReadWithBuffer(func() []byte) ([]byte, error)
	})
	var response []byte
	for {
		data, err := reader.ReadWithBuffer(func() []byte { return make([]byte, 32) })
		response = append(response, data...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if string(response) != "response" {
		t.Fatalf("half-close lost response: %q", response)
	}
}
