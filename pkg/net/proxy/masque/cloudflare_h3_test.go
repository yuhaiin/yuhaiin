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
	server := &http3.Server{TLSConfig: serverTLS, EnableDatagrams: true, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	})}
	defer server.Close()
	go func() { _ = server.Serve(socket) }()
	m := &Masque{addr: socket.LocalAddr().(*net.UDPAddr), TlsConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}}}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
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
	for conn.ipconn.MaxPacketSize() < 1280 {
		select {
		case <-ctx.Done():
			t.Fatal("QUIC path never grew to carry a minimum-MTU IPv6 packet")
		case <-time.After(10 * time.Millisecond):
		}
	}
	buf := make([]byte, packetHeadroom+1280)
	packet := buf[packetHeadroom:]
	packet[0], packet[6], packet[7] = 0x60, 17, 64
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
	if icmp, err := conn.ipconn.WritePacketBuffer(buf, packetHeadroom, len(packet)); err != nil || len(icmp) != 0 {
		t.Fatalf("write IPv6 packet: ICMP=%d, err=%v", len(icmp), err)
	}
	type result struct {
		packet []byte
		err    error
	}
	done := make(chan result, 1)
	go func() {
		b := make([]byte, 1500)
		n, err := conn.ipconn.ReadPacket(b)
		done <- result{packet: b[:n], err: err}
	}()
	select {
	case result := <-done:
		if result.err != nil || !bytes.Equal(result.packet, packet) {
			t.Fatalf("IPv6 echo length=%d, err=%v", len(result.packet), result.err)
		}
	case <-ctx.Done():
		t.Fatal("IPv6 echo did not return")
	}
}
