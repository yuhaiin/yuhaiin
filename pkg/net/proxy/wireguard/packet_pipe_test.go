package wireguard

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestPacketPipeShortReadAndOwnership(t *testing.T) {
	link := newPacketLink()
	defer link.Close()
	payload := []byte("borrowed packet")
	result := make(chan error, 1)
	go func() {
		result <- link.WritePacket(payload)
		result <- link.WritePacket(payload)
	}()
	if _, err := link.toEngine.read(make([]byte, 1)); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("short read: %v", err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	copied := make([]byte, len(payload))
	if n, err := link.toEngine.read(copied); err != nil || n != len(payload) {
		t.Fatalf("next read: %d, %v", n, err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	clear(payload)
	if string(copied) != "borrowed packet" {
		t.Fatal("read retained writer's buffer")
	}
}

func TestPacketPipeCloseUnblocksWrite(t *testing.T) {
	link := newPacketLink()
	done := make(chan error, 1)
	go func() { done <- link.WritePacket([]byte("waiting for reader")) }()
	_ = link.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("writer remained blocked after Close")
	}
}

func BenchmarkPacketPipe(b *testing.B) {
	link := newPacketLink()
	defer link.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		packet := make([]byte, 1500)
		for {
			if _, err := link.toEngine.read(packet); err != nil {
				return
			}
		}
	}()
	packet := bytes.Repeat([]byte{1}, 1400)
	b.ReportAllocs()
	for b.Loop() {
		if err := link.WritePacket(packet); err != nil {
			b.Fatal(err)
		}
	}
	_ = link.Close()
	<-done
}
