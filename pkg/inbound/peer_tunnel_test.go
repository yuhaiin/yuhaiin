package inbound

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/contract/transport"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

func peerTunnelFixture(tb testing.TB, lan netapi.Proxy) (*Inbound, netapi.Proxy) {
	tb.Helper()
	runtime := NewInbound(lan)
	tb.Cleanup(func() { _ = runtime.Close() })
	var tokenBytes [32]byte
	rand.Read(tokenBytes[:])
	token := base64.StdEncoding.EncodeToString(tokenBytes[:])
	discovery := contract.Inbound{
		ID: "discovery", Name: "Peer Discovery", Enabled: true,
		Network:  contract.NewTypedNetwork(contract.TCPUDPNetwork{Host: "127.0.0.1:0", UDP: contract.UDPUdpOnly}),
		Protocol: contract.NewTypedProtocol(contract.PeerDiscoveryProtocol{Tokens: []string{token}}),
	}
	if err := runtime.SaveContract(discovery); err != nil {
		tb.Fatal(err)
	}
	listeners := runtime.runtimeStatus(discovery).Listeners
	if len(listeners) != 1 || listeners[0].Kind != "udp" {
		tb.Fatalf("discovery runtime listeners: %+v", listeners)
	}
	addr := listeners[0].Listen
	keys := func() *ecdh.PrivateKey {
		tb.Helper()
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			tb.Fatal(err)
		}
		return key
	}
	pub, sub := keys(), keys()
	config := func(local, peer *ecdh.PrivateKey, localIP, peerIP string, routes ...string) transport.PeerTunnel {
		return transport.PeerTunnel{
			Coordinator: addr, Token: token,
			PrivateKey: base64.StdEncoding.EncodeToString(local.Bytes()), PeerPublicKey: base64.StdEncoding.EncodeToString(peer.PublicKey().Bytes()),
			LocalIP: localIP, PeerIP: peerIP, Routes: routes,
		}
	}
	publisher := contract.Inbound{
		ID: "publisher", Name: "Peer Publisher", Enabled: true, Network: contract.NewTypedNetwork(contract.EmptyNetwork{}),
		Protocol: contract.NewTypedProtocol(config(pub, sub, "10.88.1.1", "10.88.1.2", "127.0.0.1/32")),
	}
	if err := runtime.SaveContract(publisher); err != nil {
		tb.Fatal(err)
	}
	protocol, err := node.NewTypedProtocol(config(sub, pub, "10.88.1.2", "10.88.1.1", "127.0.0.0/8"))
	if err != nil {
		tb.Fatal(err)
	}
	client, err := register.ContractDialer(node.Node{ID: "client", Name: "Peer Tunnel", Origin: "manual", Enabled: true, Chain: []node.Protocol{protocol}})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = client.Close() })
	return runtime, client
}

func tcpEcho(tb testing.TB, ip string, accepted *atomic.Int32) netapi.Address {
	tb.Helper()
	listener, err := net.Listen("tcp4", net.JoinHostPort(ip, "0"))
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	addr, err := netapi.ParseSysAddr(listener.Addr())
	if err != nil {
		tb.Fatal(err)
	}
	return addr
}

func udpEcho(tb testing.TB) netapi.Address {
	tb.Helper()
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = listener.Close() })
	go func() {
		var buf [2048]byte
		for {
			n, from, err := listener.ReadFrom(buf[:])
			if err != nil {
				return
			}
			_, _ = listener.WriteTo(buf[:n], from)
		}
	}()
	addr, err := netapi.ParseSysAddr(listener.LocalAddr())
	if err != nil {
		tb.Fatal(err)
	}
	return addr
}

type peerTestLAN struct {
	netapi.Proxy
	tcpDials atomic.Int32
}

func (l *peerTestLAN) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	l.tcpDials.Add(1)
	return l.Proxy.Conn(ctx, addr)
}

func TestPeerTunnelDirectTCPAndUDP(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	lan := &peerTestLAN{Proxy: direct.Default}
	runtime, proxy := peerTunnelFixture(t, lan)
	var count atomic.Int32
	addr := tcpEcho(t, "127.0.0.1", &count)
	checkTCP := func() {
		t.Helper()
		conn, err := proxy.Conn(ctx, addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte("tunnel tcp")); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len("tunnel tcp"))
		if _, err := io.ReadFull(conn, got); err != nil || string(got) != "tunnel tcp" {
			t.Fatalf("TCP echo: %q, %v", got, err)
		}
	}
	checkTCP()
	discovery, _ := runtime.store.Load("discovery")
	if err := discovery.server.Close(); err != nil {
		t.Fatal(err)
	}
	checkTCP()
	if count.Load() != 2 {
		t.Fatalf("expected two direct target connections, got %d", count.Load())
	}

	udp := udpEcho(t)
	pc, err := proxy.PacketConn(ctx, udp)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(2 * time.Second))
	want := bytes.Repeat([]byte{13}, 512)
	if _, err := pc.WriteTo(want, udp); err != nil {
		t.Fatal(err)
	}
	var buf [1024]byte
	if n, from, err := pc.ReadFrom(buf[:]); err != nil || from.String() != udp.String() || !bytes.Equal(buf[:n], want) {
		t.Fatalf("UDP echo from %v, %d bytes, %v", from, n, err)
	}

	// The client permits all of 127/8 but the publisher only grants .1.
	forbidden, err := netapi.ParseAddress("tcp", "127.0.0.2:8080")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := proxy.Conn(ctx, forbidden)
	if err == nil {
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		_, err = conn.Read(buf[:])
	}
	if err == nil || lan.tcpDials.Load() != 2 {
		t.Fatalf("unconfigured destination was not blocked before LAN dial: error %v, total dials %d", err, lan.tcpDials.Load())
	}
}

func BenchmarkPeerTunnelTCP(b *testing.B) {
	for _, kind := range []string{"direct", "peer_tunnel"} {
		b.Run(kind, func(b *testing.B) {
			ctx, cancel := context.WithTimeout(b.Context(), 20*time.Second)
			defer cancel()
			proxy := direct.Default
			if kind == "peer_tunnel" {
				_, proxy = peerTunnelFixture(b, direct.Default)
			}
			var accepted atomic.Int32
			addr := tcpEcho(b, "127.0.0.1", &accepted)
			conn, err := proxy.Conn(ctx, addr)
			if err != nil {
				b.Fatal(err)
			}
			defer conn.Close()
			payload := bytes.Repeat([]byte{31}, 32<<10)
			result := make([]byte, len(payload))
			exchange := func() {
				b.Helper()
				if _, err := conn.Write(payload); err != nil {
					b.Fatal(err)
				}
				if _, err := io.ReadFull(conn, result); err != nil {
					b.Fatal(err)
				}
			}
			_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
			exchange()
			if !bytes.Equal(result, payload) {
				b.Fatal("echo payload changed")
			}
			b.SetBytes(int64(2 * len(payload)))
			b.ReportAllocs()
			for b.Loop() {
				exchange()
			}
		})
	}
}
