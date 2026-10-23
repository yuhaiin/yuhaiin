package wireguard

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/tailscale/wireguard-go/conn"
	wgdevice "github.com/tailscale/wireguard-go/device"
)

// The engine closes its bind before the first Open. The harness owns this
// prebound loopback socket and closes it before closing the client engine.
type loopbackTransport struct{ net.PacketConn }

func (loopbackTransport) Close() error { return nil }

// The reference peer uses the lightweight userspace IP stack and the default UDP bind.
// Traffic passes through two real WireGuard engines over loopback encryption.
func TestLightweightWireGuardInterop(t *testing.T) {
	clientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerNet, err := CreateLightweightNetTUN([]netip.Prefix{netip.MustParsePrefix("192.0.2.2/32"), netip.MustParsePrefix("2001:db8::2/128")}, 1400)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peerNet.Close() })
	peer := wgdevice.NewDevice(peerNet, conn.NewDefaultBind(), &wgdevice.Logger{Verbosef: func(string, ...any) {}, Errorf: t.Logf})
	t.Cleanup(peer.Close)
	if err := peer.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=192.0.2.1/32\nallowed_ip=2001:db8::1/128\n", hex.EncodeToString(peerKey.Bytes()), hex.EncodeToString(clientKey.PublicKey().Bytes()))); err != nil {
		t.Fatal(err)
	}
	if err := peer.Up(); err != nil {
		t.Fatal(err)
	}
	ipc, err := peer.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	port := 0
	for line := range strings.SplitSeq(ipc, "\n") {
		if value, ok := strings.CutPrefix(line, "listen_port="); ok {
			port, err = strconv.Atoi(value)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if port == 0 {
		t.Fatal("reference peer did not bind UDP")
	}
	proxy, err := NewClient(Config{
		SecretKey: base64.StdEncoding.EncodeToString(clientKey.Bytes()),
		Endpoint:  []string{"192.0.2.1/32", "2001:db8::1/128"}, MTU: 1400,
		Peers: []PeerConfig{{PublicKey: base64.StdEncoding.EncodeToString(peerKey.PublicKey().Bytes()), Endpoint: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), AllowedIPs: []string{"192.0.2.2/32", "2001:db8::2/128"}}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := proxy.(*Wireguard)
	t.Cleanup(func() { _ = client.Close() })
	// Use an unmarked loopback socket so host routing/firewall policies do not
	// redirect the test's encrypted transport to the default external interface.
	transport, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// Tailscale's engine obtains peer endpoints from configuration, not roaming.
	if err := peer.IpcSet(fmt.Sprintf("public_key=%s\nendpoint=%s\n", hex.EncodeToString(clientKey.PublicKey().Bytes()), transport.LocalAddr())); err != nil {
		t.Fatal(err)
	}
	client.bind.conn = loopbackTransport{transport}
	t.Cleanup(func() { _ = transport.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	for _, addr := range []string{"192.0.2.2:18080", "[2001:db8::2]:18080"} {
		t.Run("TCP/"+addr, func(t *testing.T) {
			remote := netip.MustParseAddrPort(addr)
			listener, err := peerNet.ListenTCP(net.TCPAddrFromAddrPort(remote))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			local, err := client.Conn(ctx, netapi.ParseNetipAddrPort("tcp", remote))
			if err != nil {
				t.Logf("client stack: %+v", client.net.stack.Stats())
				for _, engine := range []*wgdevice.Device{client.device, peer} {
					state, _ := engine.IpcGet()
					for line := range strings.SplitSeq(state, "\n") {
						name, _, _ := strings.Cut(line, "=")
						switch name {
						case "last_handshake_time_sec", "rx_bytes", "tx_bytes", "endpoint":
							t.Log(line)
						}
					}
				}
				t.Fatal(err)
			}
			defer local.Close()
			accepted, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer accepted.Close()
			_ = local.SetDeadline(time.Now().Add(10 * time.Second))
			_ = accepted.SetDeadline(time.Now().Add(10 * time.Second))
			payload := bytes.Repeat([]byte("encrypted lightweight TCP data\n"), 7000)
			written := make(chan error, 1)
			go func() {
				_, err := local.Write(payload)
				if err == nil {
					err = local.(interface{ CloseWrite() error }).CloseWrite()
				}
				written <- err
			}()
			got, err := io.ReadAll(accepted)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("upload: got %d/%d bytes, %v", len(got), len(payload), err)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			if _, err := accepted.Write([]byte("reply after FIN")); err != nil {
				t.Fatal(err)
			}
			if err := accepted.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			got, err = io.ReadAll(local)
			if err != nil || string(got) != "reply after FIN" {
				t.Fatalf("download after FIN: %q, %v", got, err)
			}
		})
	}
	t.Run("UDP/dual-stack-multiple-destinations", func(t *testing.T) {
		socket, err := client.PacketConn(ctx, netapi.EmptyAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer socket.Close()
		_ = socket.SetDeadline(time.Now().Add(10 * time.Second))
		for _, addr := range []string{"192.0.2.2:9000", "[2001:db8::2]:9000", "192.0.2.2:9001", "[2001:db8::2]:9001"} {
			dst := netip.MustParseAddrPort(addr)
			remote, err := peerNet.DialUDP(net.UDPAddrFromAddrPort(dst), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer remote.Close()
			_ = remote.SetDeadline(time.Now().Add(10 * time.Second))
			payload := []byte("encrypted UDP " + addr)
			if _, err := socket.WriteTo(payload, netapi.ParseNetipAddrPort("udp", dst)); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 1500)
			n, from, err := remote.ReadFrom(b)
			if err != nil || !bytes.Equal(b[:n], payload) {
				t.Fatalf("UDP request: %q, %v", b[:n], err)
			}
			if _, err := remote.WriteTo(b[:n], from); err != nil {
				t.Fatal(err)
			}
			n, from, err = socket.ReadFrom(b)
			if err != nil || !bytes.Equal(b[:n], payload) || from.(*net.UDPAddr).AddrPort() != dst {
				t.Fatalf("UDP reply: %q from %v, %v", b[:n], from, err)
			}
		}
		_ = socket.SetReadDeadline(time.Now().Add(-time.Second))
		if _, _, err := socket.ReadFrom(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("UDP deadline: %v", err)
		}
	})
	t.Run("TCP/cancel", func(t *testing.T) {
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		socket, err := client.net.DialContextTCP(canceled, net.TCPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.2:18081")))
		if !errors.Is(err, context.Canceled) || socket != nil {
			t.Fatalf("canceled dial: %T, %v", socket, err)
		}
	})
	t.Run("TCP/dual-stack-ephemeral-listener", func(t *testing.T) {
		listener, err := client.net.ListenTCP(nil)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		port := listener.Addr().(*net.TCPAddr).Port
		if port == 0 {
			t.Fatal("listener did not select an ephemeral port")
		}
		for _, host := range []string{"192.0.2.1", "2001:db8::1"} {
			local, err := peerNet.DialContextTCP(ctx, net.TCPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(host), uint16(port))))
			if err != nil {
				t.Logf("client stack: %+v", client.net.stack.Stats())
				for _, engine := range []*wgdevice.Device{client.device, peer} {
					state, _ := engine.IpcGet()
					for line := range strings.SplitSeq(state, "\n") {
						name, _, _ := strings.Cut(line, "=")
						switch name {
						case "last_handshake_time_sec", "rx_bytes", "tx_bytes", "endpoint":
							t.Log(line)
						}
					}
				}
				t.Fatal(err)
			}
			defer local.Close()
			accepted, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			if accepted.LocalAddr().(*net.TCPAddr).IP.String() != host {
				t.Fatal("accepted incorrect family")
			}
			_ = accepted.Close()
		}
	})
}
