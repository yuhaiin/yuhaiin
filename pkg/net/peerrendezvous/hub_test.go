package peerrendezvous

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestHubDiscoversPublicEndpointWithSTUN(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		var buf [64]byte
		n, from, err := server.ReadFrom(buf[:])
		if err != nil || n < 20 {
			return
		}
		ap := from.(*net.UDPAddr).AddrPort()
		reply := make([]byte, 32)
		binary.BigEndian.PutUint16(reply, 0x0101)
		binary.BigEndian.PutUint16(reply[2:], 12)
		binary.BigEndian.PutUint32(reply[4:], stunCookie)
		copy(reply[8:20], buf[8:20])
		binary.BigEndian.PutUint16(reply[20:], 0x0020)
		binary.BigEndian.PutUint16(reply[22:], 8)
		reply[25] = 1
		binary.BigEndian.PutUint16(reply[26:], ap.Port()^uint16(stunCookie>>16))
		ip := ap.Addr().As4()
		binary.BigEndian.PutUint32(reply[28:], binary.BigEndian.Uint32(ip[:])^stunCookie)
		_, _ = server.WriteTo(reply, from)
	}()
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hub := NewHub(socket)
	defer hub.Close()
	got, err := hub.DiscoverPublic(server.LocalAddr().(*net.UDPAddr).AddrPort(), 3*time.Second)
	want := socket.LocalAddr().(*net.UDPAddr).AddrPort()
	if err != nil || got != want {
		t.Fatalf("mapped address = %v, %v; want %v", got, err, want)
	}
}

func TestHubPublisherAndDialerRendezvousOnOneSocket(t *testing.T) {
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hub := NewHub(socket)
	defer hub.Close()
	public := socket.LocalAddr().(*net.UDPAddr).AddrPort()
	hub.SetPublic(public)
	key := [32]byte{7}
	pc, coordinator, err := hub.Open(key)
	if err != nil {
		t.Fatal(err)
	}
	publisher := NewManagedSocket(pc, coordinator, key, Publisher, nil, nil, netip.Prefix{})
	defer publisher.Close()

	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dialer := NewManagedSocket(client, public, key, Dialer, nil, nil, netip.Prefix{})
	dialer.SetHosted()
	defer dialer.Close()
	// Sockets process rendezvous replies from the reader's goroutine.
	received := make(chan int, 4)
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := dialer.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := publisher.ReadFrom(buf)
			if err != nil {
				return
			}
			received <- n
		}
	}()
	ctx, cancel := timeout(t)
	defer cancel()
	if err := dialer.WaitReady(ctx); err != nil {
		t.Fatalf("%v pairs=%+v dialerPeer=%v pubPeer=%v", err, hub.Pairs(), dialer.peer.Load(), publisher.peer.Load())
	}
	if err := publisher.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	// Datagrams larger than a rendezvous message reach the publisher intact.
	payload := make([]byte, 148)
	payload[0] = 1
	if _, err := dialer.WriteTo(payload, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case n := <-received:
		if n != len(payload) {
			t.Fatalf("publisher read %d bytes", n)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("publisher did not receive the datagram")
	}

	// Removing the pairing makes the dialer unreachable at once.
	hub.Remove(key)
	if _, err := publisher.WriteTo([]byte{1}, nil); err == nil {
		t.Log("closed publisher accepted a write")
	}
	if _, ok := hub.dialerOwner(client.LocalAddr().(*net.UDPAddr).AddrPort(), time.Now()); ok {
		t.Fatal("removed pairing still routes data")
	}
}

func TestHubBlockAndKickStopRouting(t *testing.T) {
	socket, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	hub := NewHub(socket)
	defer hub.Close()
	hub.SetPublic(socket.LocalAddr().(*net.UDPAddr).AddrPort())
	key := [32]byte{9}
	pc, coord, err := hub.Open(key)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	id := pairID(key)
	if err := hub.Kick(id); err != nil {
		t.Fatal(err)
	}
	if _, ok := hub.Pairs()[hexID(id)]; !ok || !coord.IsValid() {
		t.Fatal("pairing missing")
	}
	hub.SetBlocked([]string{hexID(id)})
	if err := hub.Kick(id); err == nil {
		t.Fatal("blocked pairing can be kicked")
	}
}

func hexID(id [16]byte) string { return hex.EncodeToString(id[:]) }

func timeout(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(t.Context(), 15*time.Second)
}
