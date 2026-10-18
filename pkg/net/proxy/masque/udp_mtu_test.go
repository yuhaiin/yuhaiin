package masque

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

// A peer's receive MTU is not a promise about its transmitted IP packet size.
// In particular, a 1280-byte QUIC UDP payload has additional IP and UDP headers.
func TestUDPReplyLargerThanConfiguredMTU(t *testing.T) {
	for _, family := range []string{"ipv4", "ipv6"} {
		t.Run(family, func(t *testing.T) { testUDPReplyLargerThanMTU(t, family) })
	}
}

func testUDPReplyLargerThanMTU(t *testing.T, family string) {
	clientIP, serverIP := "192.0.2.2/32", "192.0.2.53/32"
	if family == "ipv6" {
		clientIP, serverIP = "2001:db8::2/128", "2001:db8::53/128"
	}
	peer, err := wireguard.CreateLightweightNetTUN([]netip.Prefix{netip.MustParsePrefix(serverIP)}, 1500)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	address := &net.UDPAddr{IP: net.ParseIP(netip.MustParsePrefix(serverIP).Addr().String()), Port: 853}
	udp, err := peer.DialUDP(address, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	certServer := httptest.NewTLSServer(nil)
	serverTLS := certServer.TLS.Clone()
	certServer.Close()
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	server := &http3.Server{TLSConfig: serverTLS, EnableDatagrams: true, QUICConfig: &quic.Config{EnableDatagrams: true, InitialPacketSize: 1450}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stop := context.AfterFunc(r.Context(), func() { _ = udp.Close(); _ = peer.Close() })
		defer stop()
		w.WriteHeader(http.StatusOK)
		stream := w.(http3.HTTPStreamer).HTTPStream()
		go func() {
			for {
				data, err := stream.ReceiveDatagram(r.Context())
				if err != nil {
					return
				}
				if len(data) > 0 && data[0] == 0 {
					if _, err := peer.Write([][]byte{data[1:]}, 0); err != nil {
						return
					}
				}
			}
		}()
		go func() {
			buf := make([]byte, 65536)
			for {
				n, err := peer.ReadPacket(buf[1:])
				if err != nil {
					return
				}
				if err := stream.SendDatagram(buf[:n+1]); err != nil {
					return
				}
			}
		}()
		buf := make([]byte, 1500)
		for {
			n, from, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			if n == 0 {
				continue
			}
			if _, err := udp.WriteTo(bytes.Repeat(buf[:1], 1280), from); err != nil {
				return
			}
		}
	})}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Serve(socket) }()
	m, err := NewMasque(direct.Default, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}}, socket.LocalAddr().(*net.UDPAddr), []netip.Prefix{netip.MustParsePrefix(clientIP)}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	pc, err := m.PacketConn(context.Background(), netapi.EmptyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	_ = pc.SetDeadline(time.Now().Add(4 * time.Second))
	for _, value := range []byte{0xa5, 0x5a} {
		if _, err := pc.WriteTo([]byte{value}, address); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1500)
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("receive 1280-byte UDP payload with MTU 1280: %v", err)
		}
		if !bytes.Equal(buf[:n], bytes.Repeat([]byte{value}, 1280)) || from.String() != address.String() {
			t.Fatalf("corrupt reply: len=%d from=%v", n, from)
		}
	}
}
