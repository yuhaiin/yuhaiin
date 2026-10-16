package wireguard

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestLightweightNetTunCloseWithPacketInFlight(t *testing.T) {
	n, err := CreateLightweightNetTUN([]netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}, 1400)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = n.Close() })
	if _, err := n.stack.WriteUDP(netip.MustParseAddrPort("192.0.2.1:1000"), netip.MustParseAddrPort("192.0.2.2:2000"), []byte("in flight")); err != nil {
		t.Fatal(err)
	}
	var borrowed []byte
	select {
	case borrowed = <-n.link.toEngine.packets:
	case <-time.After(time.Second):
		t.Fatal("packet did not reach engine")
	}
	done := make(chan struct{})
	go func() { _ = n.Close(); close(done) }()
	<-n.link.done
	select {
	case <-done:
		t.Fatal("Close released a packet still borrowed by the engine")
	case <-time.After(10 * time.Millisecond):
	}
	if !bytes.HasSuffix(borrowed, []byte("in flight")) {
		t.Fatal("in-flight data changed during Close")
	}
	n.link.toEngine.copied <- struct{}{}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close deadlocked after engine released packet")
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLightweightNetTunCloseUnblocksRead(t *testing.T) {
	n, err := CreateLightweightNetTUN([]netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}, 1400)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := n.ReadPacket(make([]byte, 1500)); done <- err }()
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("engine Read remained blocked after Close")
	}
}
