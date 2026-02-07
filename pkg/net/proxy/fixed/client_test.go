package fixed

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"google.golang.org/protobuf/proto"
)

func TestUdpDetect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s, err := NewServer(config.Tcpudp_builder{
		Host:             proto.String("127.0.0.1:0"),
		UdpHappyEyeballs: proto.Bool(true),
	}.Build())
	assert.NoError(t, err)

	mockServer, err := s.Packet(ctx)
	assert.NoError(t, err)
	defer mockServer.Close()

	// Get the actual address the mock server is listening on
	actualServerUDPAddr, ok := mockServer.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("mock server local address is not a UDPAddr: %T", mockServer.LocalAddr())
	}
	actualServerAddrPort := netip.MustParseAddrPort(actualServerUDPAddr.String())

	t.Logf("Mock UDP server listening on %s", actualServerAddrPort.String())

	// Create a fixed.Client with udpDetect enabled
	fixedNode := node.Fixedv2_builder{
		Addresses: []*node.Fixedv2Address{
			node.Fixedv2Address_builder{
				Host: proto.String(actualServerAddrPort.String()),
			}.Build(),
			node.Fixedv2Address_builder{
				Host: proto.String(actualServerAddrPort.String()),
			}.Build(),
		},
		UdpHappyEyeballs: proto.Bool(true),
	}.Build()

	client, err := NewClientv2(fixedNode, nil) // passing nil for proxy since we're testing direct UDP
	assert.NoError(t, err)

	laddr, _ := netapi.ParseSysAddr(mockServer.LocalAddr().(*net.UDPAddr))
	// Call PacketConn to trigger UDP detection
	packetConn, err := client.PacketConn(ctx, laddr)
	assert.NoError(t, err)
	defer packetConn.Close()

	t.Log("PacketConn established successfully with UDP detection.")

	// Test if writing to the PacketConn sends data to the detected address
	testData := []byte("hello udp")

	_, err = packetConn.WriteTo(testData, mockServer.LocalAddr().(*net.UDPAddr)) // Destination doesn't matter much here, as WriteTo will use the detected addr
	assert.NoError(t, err)

	// Read from the mock server to confirm data was received
	readBuf := make([]byte, 1024)
	n, remoteAddr, err := mockServer.ReadFrom(readBuf)
	assert.NoError(t, err)

	if !bytes.Equal(readBuf[:n], testData) {
		t.Errorf("mock server received unexpected data: got %q, want %q", readBuf[:n], testData)
	}
	t.Logf("Mock server received data %q from %s", readBuf[:n], remoteAddr.String())
}

func TestOptimizationLeak(t *testing.T) {
	// 1. Setup
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s, err := NewServer(config.Tcpudp_builder{
		Host:             proto.String("127.0.0.1:0"),
		UdpHappyEyeballs: proto.Bool(true),
	}.Build())
	assert.NoError(t, err)

	mockServer, err := s.Packet(ctx)
	assert.NoError(t, err)
	defer mockServer.Close()

	actualServerUDPAddr := mockServer.LocalAddr().(*net.UDPAddr)
	actualServerAddrPort := netip.MustParseAddrPort(actualServerUDPAddr.String())

	fixedNode := node.Fixedv2_builder{
		Addresses: []*node.Fixedv2Address{
			node.Fixedv2Address_builder{
				Host: proto.String(actualServerAddrPort.String()),
			}.Build(),
			node.Fixedv2Address_builder{ // Add a second address so logic triggers
				Host: proto.String(actualServerAddrPort.String()),
			}.Build(),
		},
		UdpHappyEyeballs: proto.Bool(true),
	}.Build()

	client, err := NewClientv2(fixedNode, nil)
	assert.NoError(t, err)

	// 2. Baseline Goroutines
	// Give a moment for things to settle
	time.Sleep(100 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()
	t.Logf("Initial Goroutines: %d", initialGoroutines)

	// 3. Trigger PacketConn
	laddr, _ := netapi.ParseSysAddr(mockServer.LocalAddr().(*net.UDPAddr))
	packetConn, err := client.PacketConn(ctx, laddr)
	assert.NoError(t, err)
	defer packetConn.Close()

	t.Log("PacketConn returned (success)")

	// 4. Measure
	// We wait 100ms.
	// In the inefficient version, the loop sleeps 200ms between iterations (3 times).
	// So even if it succeeded immediately (iteration 0), it will sleep at least 200ms before iteration 1.
	// Thus, the writer goroutine should still be alive at T+100ms.
	time.Sleep(100 * time.Millisecond)

	currentGoroutines := runtime.NumGoroutine()
	diff := currentGoroutines - initialGoroutines
	t.Logf("Current Goroutines: %d (Diff: %d)", currentGoroutines, diff)

	// In the unoptimized version, we expect the writer goroutine to still be running.
	// We also expect the reader goroutine to be finished (it exits on success).
	// So diff should be >= 1.
	// Ideally, we want diff to be 0 (everything cleaned up).

	if diff > 0 {
		t.Logf("Optimization opportunity found: %d extra goroutines running after 100ms", diff)
		// Fail the test if we are verifying the fix
		t.Fail()
	} else {
		t.Logf("No lingering goroutines found (Diff: %d)", diff)
	}
}
