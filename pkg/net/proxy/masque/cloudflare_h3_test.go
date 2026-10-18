package masque

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

func TestCloudflareHTTP3BBRDiscoversTunnelMTU(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) { testCloudflareHTTP3BBRTunnel(t, network) })
	}
}

func testCloudflareHTTP3BBRTunnel(t *testing.T, network string) {
	certServer := httptest.NewTLSServer(nil)
	serverTLS := certServer.TLS.Clone()
	certServer.Close()
	host := "127.0.0.1:0"
	if network == "udp6" {
		host = "[::1]:0"
	}
	socket, err := net.ListenPacket(network, host)
	if err != nil {
		if network == "udp6" && (errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL)) {
			t.Skipf("IPv6 loopback unavailable: %v", err)
		}
		t.Fatal(err)
	}
	defer socket.Close()
	// This is a loopback echo peer, not the MTU under test. Give it enough
	// outbound packet capacity to echo the 1280-byte inner IPv6 datagram;
	// otherwise a successful *client* PMTU discovery can still time out
	// because the echo server has not discovered its own return-path MTU.
	server := &http3.Server{
		TLSConfig:       serverTLS,
		QUICConfig:      &quic.Config{InitialPacketSize: 1400},
		EnableDatagrams: true,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Proto != "cf-connect-ip" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		stream := w.(http3.HTTPStreamer).HTTPStream()
		for {
			b, err := stream.ReceiveDatagram(r.Context())
			if err != nil {
				return
			}
			if err := stream.SendDatagram(b); err != nil {
				return
			}
		}
		}),
	}
	defer server.Close()
	go func() { _ = server.Serve(socket) }()
	m := &Masque{addr: socket.LocalAddr().(*net.UDPAddr), TlsConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}}}
	// Keep the CONNECT request context alive while PMTU discovery and the echo run.
	// QUIC sends MTU probes on an RTT-based schedule, which can be delayed by -race.
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	conn, err := m.connectOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	local := conn.packetConn.LocalAddr().(*net.UDPAddr)
	if (local.IP.To4() != nil) != (m.addr.IP.To4() != nil) {
		t.Fatalf("outer socket family %v does not match endpoint %v", local, m.addr)
	}
	// Drain small echo packets while probing so the HTTP/3 datagram receive
	// queue doesn't fill up. Only the final 1280-byte echo completes the test.
	type result struct {
		packet []byte
		err    error
	}
	done := make(chan result, 1)
	go func() {
		for {
			b := make([]byte, 1500)
			n, err := conn.ipconn.ReadPacket(b)
			if err != nil {
				done <- result{err: err}
				return
			}
			if n == 1280 {
				done <- result{packet: b[:n]}
				return
			}
		}
	}()

	// A read-only MaxPacketSize poll doesn't generate QUIC packets. Periodic
	// small CONNECT-IP datagrams exercise the actual tunnel and give the QUIC
	// sender opportunities to perform ack-based PMTU discovery.
	mtuCtx, cancelMTU := context.WithTimeout(ctx, 10*time.Second)
	defer cancelMTU()
	mtuTicker := time.NewTicker(50 * time.Millisecond)
	defer mtuTicker.Stop()
	probeBuf := make([]byte, packetHeadroom+64)
	probe := probeBuf[packetHeadroom:]
	probe[0], probe[6] = 0x60, 17
	binary.BigEndian.PutUint16(probe[4:6], uint16(len(probe)-40))
	for {
		maxPacketSize := conn.ipconn.MaxPacketSize()
		if maxPacketSize >= 1280 {
			break
		}
		probe[7] = 64 // WritePacketBuffer decrements the IPv6 hop limit.
		if icmp, err := conn.ipconn.WritePacketBuffer(probeBuf, packetHeadroom, len(probe)); err != nil || len(icmp) != 0 {
			t.Fatalf("write PMTU keepalive packet: ICMP=%d, err=%v", len(icmp), err)
		}
		select {
		case result := <-done:
			t.Fatalf("read during PMTU discovery: %v (packet length=%d)", result.err, len(result.packet))
		case <-mtuCtx.Done():
			t.Fatalf("QUIC path never grew to carry a minimum-MTU IPv6 packet: max packet size=%d, err=%v", maxPacketSize, mtuCtx.Err())
		case <-mtuTicker.C:
		}
	}
	buf := make([]byte, packetHeadroom+1280)
	packet := buf[packetHeadroom:]
	packet[0], packet[6], packet[7] = 0x60, 17, 64
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
	if icmp, err := conn.ipconn.WritePacketBuffer(buf, packetHeadroom, len(packet)); err != nil || len(icmp) != 0 {
		t.Fatalf("write IPv6 packet: ICMP=%d, err=%v", len(icmp), err)
	}
	echoCtx, cancelEcho := context.WithTimeout(ctx, 5*time.Second)
	defer cancelEcho()
	select {
	case result := <-done:
		if result.err != nil || !bytes.Equal(result.packet, packet) {
			t.Fatalf("IPv6 echo length=%d, err=%v", len(result.packet), result.err)
		}
	case <-echoCtx.Done():
		t.Fatalf("IPv6 echo did not return: %v", echoCtx.Err())
	}
}
