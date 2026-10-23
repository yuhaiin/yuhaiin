package wireguard

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/tailscale/wireguard-go/conn"
	wgdevice "github.com/tailscale/wireguard-go/device"
)

type inboundReferenceHandler struct {
	inboundBenchmarkHandler
	sources chan net.Addr
}

func (h inboundReferenceHandler) HandlePacket(p *netapi.Packet) {
	h.sources <- p.Src()
	h.inboundBenchmarkHandler.HandlePacket(p)
}

// Use a lightweight reference client, independently of the inbound lightweight
// stack, with a real encrypted UDP transport and preshared keys.
func TestWireGuardInboundReferencePeers(t *testing.T) {
	server, first := inboundTestConfigs(t)
	otherServer, second := inboundTestConfigs(t)
	server.Peers = append(server.Peers, otherServer.Peers[0])
	server.Peers[1].AllowedIPs = []string{"10.66.0.3/32", "fd66::3/128"}
	second.Endpoint = []string{"10.66.0.3/32", "fd66::3/128"}
	second.Peers[0].PublicKey = first.Peers[0].PublicKey
	sources := make(chan net.Addr, 128)
	port, _ := startInboundTestServer(t, server, inboundReferenceHandler{sources: sources})
	t.Cleanup(func() {
		if len(sources) == 0 {
			t.Error("no UDP packets reached the handler")
		}
		for len(sources) > 0 {
			if source := (<-sources).(*net.UDPAddr); source.IP.String() == "10.66.0.99" {
				t.Errorf("disallowed source reached the inbound handler: %v", source)
			}
		}
	})
	for i, config := range []Config{first, second} {
		t.Run(fmt.Sprintf("peer-%d", i), func(t *testing.T) {
			t.Parallel()
			prefixes := make([]netip.Prefix, 0, len(config.Endpoint)+1)
			for _, address := range config.Endpoint {
				prefixes = append(prefixes, netip.MustParsePrefix(address))
			}
			prefixes = append(prefixes, netip.MustParsePrefix("10.66.0.99/32"))
			client, err := CreateLightweightNetTUN(prefixes, 1420)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			engine := wgdevice.NewDevice(client, conn.NewDefaultBind(), &wgdevice.Logger{
				Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {},
			})
			t.Cleanup(engine.Close)
			private, _ := base64.StdEncoding.DecodeString(config.SecretKey)
			public, _ := base64.StdEncoding.DecodeString(config.Peers[0].PublicKey)
			psk, _ := base64.StdEncoding.DecodeString(config.Peers[0].PreSharedKey)
			if err := engine.IpcSet(fmt.Sprintf("private_key=%s\npublic_key=%s\npreshared_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n",
				hex.EncodeToString(private), hex.EncodeToString(public), hex.EncodeToString(psk), port)); err != nil {
				t.Fatal(err)
			}
			if err := engine.Up(); err != nil {
				t.Fatal(err)
			}
			for _, address := range []string{"198.51.100.7:9000", "[2001:db8::7]:9000"} {
				t.Run(address, func(t *testing.T) {
					dst := netip.MustParseAddrPort(address)
					t.Run("TCP-half-close", func(t *testing.T) {
						socket, err := client.DialContextTCP(t.Context(), net.TCPAddrFromAddrPort(dst))
						if err != nil {
							t.Fatal(err)
						}
						defer socket.Close()
						_ = socket.SetDeadline(time.Now().Add(10 * time.Second))
						payload := bytes.Repeat([]byte("encrypted inbound reference peer\n"), 8192)
						written := make(chan error, 1)
						go func() {
							_, err := socket.Write(append([]byte{'E'}, payload...))
							if err == nil {
								err = socket.CloseWrite()
							}
							written <- err
						}()
						got, err := io.ReadAll(socket)
						if err != nil || !bytes.Equal(got, payload) {
							t.Fatalf("TCP echo: %d/%d bytes: %v", len(got), len(payload), err)
						}
						if err := <-written; err != nil {
							t.Fatal(err)
						}
					})
					t.Run("UDP", func(t *testing.T) {
						socket, err := client.DialUDP(nil, net.UDPAddrFromAddrPort(dst))
						if err != nil {
							t.Fatal(err)
						}
						defer socket.Close()
						_ = socket.SetDeadline(time.Now().Add(5 * time.Second))
						payload := bytes.Repeat([]byte{byte(i)}, 1200)
						for range 16 {
							if _, err := socket.Write(payload); err != nil {
								t.Fatal(err)
							}
							got := make([]byte, 1500)
							n, from, err := socket.ReadFrom(got)
							if err != nil || !bytes.Equal(got[:n], payload) || from.(*net.UDPAddr).AddrPort() != dst {
								t.Fatalf("UDP echo: %d bytes from %v: %v", n, from, err)
							}
						}
					})
				})
			}
			t.Run("authenticated-roaming", func(t *testing.T) {
				before, err := engine.IpcGet()
				if err != nil {
					t.Fatal(err)
				}
				if err := engine.IpcSet("listen_port=0\n"); err != nil {
					t.Fatal(err)
				}
				after, err := engine.IpcGet()
				if err != nil {
					t.Fatal(err)
				}
				portLine := func(state string) string {
					for line := range strings.SplitSeq(state, "\n") {
						if strings.HasPrefix(line, "listen_port=") {
							return line
						}
					}
					return ""
				}
				if portLine(before) == portLine(after) {
					t.Fatal("client did not change its UDP endpoint")
				}
				socket, err := client.DialUDP(nil, &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 9000})
				if err != nil {
					t.Fatal(err)
				}
				defer socket.Close()
				_ = socket.SetDeadline(time.Now().Add(5 * time.Second))
				payload := []byte("authenticated packet from a new UDP endpoint")
				if _, err := socket.Write(payload); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, 1500)
				if n, err := socket.Read(got); err != nil || !bytes.Equal(got[:n], payload) {
					t.Fatalf("reply after roaming: %d bytes: %v", n, err)
				}
			})
			t.Run("reject-spoofed-source", func(t *testing.T) {
				socket, err := client.DialUDP(&net.UDPAddr{IP: net.ParseIP("10.66.0.99"), Port: 19001}, &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 9000})
				if err != nil {
					t.Fatal(err)
				}
				defer socket.Close()
				_ = socket.SetDeadline(time.Now().Add(150 * time.Millisecond))
				if _, err := socket.Write([]byte("not an allowed source")); err != nil {
					t.Fatal(err)
				}
				if _, err := socket.Read(make([]byte, 1500)); err == nil {
					t.Fatal("server echoed traffic outside the peer's AllowedIPs")
				} else if timeout, ok := errors.AsType[net.Error](err); !ok || !timeout.Timeout() {
					t.Fatalf("expected read timeout: %v", err)
				}
			})
		})
	}
}
