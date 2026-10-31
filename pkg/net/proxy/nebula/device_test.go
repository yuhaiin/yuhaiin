package nebula

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	"github.com/slackhq/nebula/overlay/tio"
)

type udpInjectFixture struct {
	device  *memoryDevice
	server  net.PacketConn
	packet  []byte
	payload []byte
}

func newUDPInjectFixture(tb testing.TB, payload []byte) udpInjectFixture {
	tb.Helper()

	localPrefix := netip.MustParsePrefix("192.0.2.1/32")
	peerPrefix := netip.MustParsePrefix("192.0.2.2/32")
	local, err := wireguard.CreateLightweightNetTUN([]netip.Prefix{localPrefix}, 1400)
	if err != nil {
		tb.Fatal(err)
	}
	peer, err := wireguard.CreateLightweightNetTUN([]netip.Prefix{peerPrefix}, 1400)
	if err != nil {
		_ = local.Close()
		tb.Fatal(err)
	}
	server, err := local.Stack().ListenUDP(netip.MustParseAddrPort("192.0.2.1:4242"))
	if err != nil {
		_ = peer.Close()
		_ = local.Close()
		tb.Fatal(err)
	}
	client, err := peer.DialUDP(nil, net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:4242")))
	if err != nil {
		_ = server.Close()
		_ = peer.Close()
		_ = local.Close()
		tb.Fatal(err)
	}
	tb.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
		_ = peer.Close()
		_ = local.Close()
	})

	writeDone := make(chan error, 1)
	go func() {
		n, err := client.Write(payload)
		if err == nil && n != len(payload) {
			err = io.ErrShortWrite
		}
		writeDone <- err
	}()
	packetBuffer := make([]byte, 1400)
	readDone := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := peer.ReadPacket(packetBuffer)
		readDone <- struct {
			n   int
			err error
		}{n: n, err: err}
	}()
	var packetN int
	select {
	case result := <-readDone:
		if result.err != nil {
			tb.Fatal(result.err)
		}
		packetN = result.n
	case <-time.After(time.Second):
		tb.Fatal("lightweight stack did not emit the UDP packet")
	}
	select {
	case err := <-writeDone:
		if err != nil {
			tb.Fatal(err)
		}
	case <-time.After(time.Second):
		tb.Fatal("UDP write did not finish after packet was read")
	}

	return udpInjectFixture{
		device:  &memoryDevice{network: local, networks: []netip.Prefix{localPrefix}},
		server:  server,
		packet:  packetBuffer[:packetN],
		payload: payload,
	}
}

func TestMemoryDeviceWriteInjectsUDPIntoLightweightStack(t *testing.T) {
	fixture := newUDPInjectFixture(t, []byte("nebula inbound UDP"))
	queues, err := fixture.device.Queues(1)
	if err != nil || len(queues) != 1 {
		t.Fatalf("device queues: count=%d err=%v", len(queues), err)
	}
	writeDone := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := queues[0].Write(fixture.packet)
		writeDone <- struct {
			n   int
			err error
		}{n: n, err: err}
	}()
	select {
	case result := <-writeDone:
		if result.err != nil || result.n != len(fixture.packet) {
			t.Fatalf("overlay device write: n=%d err=%v", result.n, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("overlay device write did not deliver the packet to the lightweight stack")
	}

	if err := fixture.server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len(fixture.payload))
	n, _, err := fixture.server.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(fixture.payload) || !bytes.Equal(buffer[:n], fixture.payload) {
		t.Fatalf("received %q; want %q", buffer[:n], fixture.payload)
	}
}

func TestMemoryDevicesBridgeTCP(t *testing.T) {
	leftNetwork, err := wireguard.CreateLightweightNetTUN([]netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}, 1400)
	if err != nil {
		t.Fatal(err)
	}
	rightNetwork, err := wireguard.CreateLightweightNetTUN([]netip.Prefix{netip.MustParsePrefix("192.0.2.2/32")}, 1400)
	if err != nil {
		_ = leftNetwork.Close()
		t.Fatal(err)
	}
	left := &memoryDevice{network: leftNetwork}
	right := &memoryDevice{network: rightNetwork}
	leftQueues, err := left.Queues(4)
	if err != nil || len(leftQueues) != 1 {
		_ = right.Close()
		_ = left.Close()
		t.Fatalf("left device queues: count=%d err=%v", len(leftQueues), err)
	}
	rightQueues, err := right.Queues(1)
	if err != nil || len(rightQueues) != 1 {
		_ = right.Close()
		_ = left.Close()
		t.Fatalf("right device queues: count=%d err=%v", len(rightQueues), err)
	}
	listener, err := rightNetwork.ListenTCP(&net.TCPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 4242})
	if err != nil {
		_ = rightNetwork.Close()
		_ = leftNetwork.Close()
		t.Fatal(err)
	}

	var pumps sync.WaitGroup
	pump := func(from, to tio.Queue) {
		for {
			packets, err := from.Read()
			if err != nil {
				return
			}
			for _, packet := range packets {
				if _, err := to.Write(packet.Bytes); err != nil {
					return
				}
			}
		}
	}
	pumps.Go(func() { pump(leftQueues[0], rightQueues[0]) })
	pumps.Go(func() { pump(rightQueues[0], leftQueues[0]) })
	t.Cleanup(func() {
		_ = listener.Close()
		_ = left.Close()
		_ = right.Close()
		pumps.Wait()
	})

	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, err := listener.Accept()
		accepted <- acceptResult{conn: conn, err: err}
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, err := leftNetwork.DialContextTCP(ctx, &net.TCPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 4242})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var server net.Conn
	select {
	case result := <-accepted:
		if result.err != nil {
			t.Fatal(result.err)
		}
		server = result.conn
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()
	deadline := time.Now().Add(5 * time.Second)
	if err := client.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := server.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}

	want := []byte("lightweight TCP across Nebula overlay devices")
	echoDone := make(chan error, 1)
	go func() {
		got := make([]byte, len(want))
		if _, err := io.ReadFull(server, got); err != nil {
			echoDone <- err
			return
		}
		if !bytes.Equal(got, want) {
			echoDone <- errors.New("server received different TCP payload")
			return
		}
		_, err := server.Write(got)
		echoDone <- err
	}()
	if _, err := client.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("received %q; want %q", got, want)
	}
	if err := <-echoDone; err != nil {
		t.Fatal(err)
	}
}

func BenchmarkMemoryDeviceUDPInject(b *testing.B) {
	payload := bytes.Repeat([]byte{0xa5}, 64)
	fixture := newUDPInjectFixture(b, payload)
	buffer := make([]byte, len(payload))
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for b.Loop() {
		if n, err := fixture.device.Write(fixture.packet); err != nil || n != len(fixture.packet) {
			b.Fatalf("overlay device write: n=%d err=%v", n, err)
		}
		n, _, err := fixture.server.ReadFrom(buffer)
		if err != nil || n != len(payload) || !bytes.Equal(buffer[:n], payload) {
			b.Fatalf("received %d bytes, err=%v", n, err)
		}
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "packets/s")
}
