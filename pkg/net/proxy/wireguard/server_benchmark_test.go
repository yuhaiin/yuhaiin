package wireguard

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight"
	"github.com/tailscale/wireguard-go/conn"
)

const inboundBenchmarkBlock = 256 << 10

type inboundBenchmarkHandler struct{}

func (inboundBenchmarkHandler) HandlePing(*netapi.PingMeta) {}
func (inboundBenchmarkHandler) HandlePacket(p *netapi.Packet) {
	defer p.DecRef()
	_, _ = p.WriteBack(p.GetPayload(), p.Dst())
}
func (inboundBenchmarkHandler) HandleStream(m *netapi.StreamMeta) {
	defer m.Src.Close()
	_ = m.Src.SetDeadline(time.Now().Add(2 * time.Minute))
	var mode [1]byte
	if _, err := io.ReadFull(m.Src, mode[:]); err != nil {
		return
	}
	if mode[0] == 'E' {
		_, _ = io.Copy(m.Src, m.Src)
		return
	}
	block := bytes.Repeat([]byte{0x5a}, inboundBenchmarkBlock)
	for {
		if mode[0] == 'U' {
			if _, err := io.ReadFull(m.Src, block); err != nil {
				return
			}
			if _, err := m.Src.Write(mode[:]); err != nil {
				return
			}
		} else {
			if _, err := io.ReadFull(m.Src, mode[:]); err != nil {
				return
			}
			if _, err := m.Src.Write(block); err != nil {
				return
			}
		}
	}
}

func inboundTestConfigs(tb testing.TB) (ServerConfig, Config) {
	tb.Helper()
	keys := make([]*ecdh.PrivateKey, 2)
	for i := range keys {
		var err error
		keys[i], err = ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			tb.Fatal(err)
		}
	}
	server := ServerConfig{
		PrivateKey: base64.StdEncoding.EncodeToString(keys[0].Bytes()),
		Addresses:  []string{"10.66.0.1/24", "fd66::1/64"}, MTU: 1420,
		Peers: []ServerPeer{{PublicKey: base64.StdEncoding.EncodeToString(keys[1].PublicKey().Bytes()),
			PreSharedKey: testWGKey(3), AllowedIPs: []string{"10.66.0.2/32", "fd66::2/128"}}},
	}
	client := Config{
		SecretKey: base64.StdEncoding.EncodeToString(keys[1].Bytes()),
		Endpoint:  []string{"10.66.0.2/32", "fd66::2/128"}, MTU: 1420,
		Peers: []PeerConfig{{PublicKey: base64.StdEncoding.EncodeToString(keys[0].PublicKey().Bytes()),
			PreSharedKey: testWGKey(3), AllowedIPs: []string{"0.0.0.0/0", "::/0"}}},
	}
	return server, client
}

func startInboundTestServer(tb testing.TB, config ServerConfig, handler netapi.Handler) (int, *inboundServer) {
	tb.Helper()
	probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	config.ListenPort = probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()
	server, err := NewServer(config, handler)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = server.Close() })
	return config.ListenPort, server.(*inboundServer)
}

func startInboundTestClient(tb testing.TB, config Config, port int) *Wireguard {
	tb.Helper()
	config.Peers[0].Endpoint = fmt.Sprintf("127.0.0.1:%d", port)
	proxy, err := NewClient(config, nil)
	if err != nil {
		tb.Fatal(err)
	}
	client := proxy.(*Wireguard)
	transport, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		_ = client.Close()
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = transport.Close(); _ = client.Close() })
	// Match the production dialer's receive buffer. The default UDP buffer
	// overflows during loopback downloads and measures TCP loss recovery.
	if err := transport.(*net.UDPConn).SetReadBuffer(dialer.SocketBufferSize); err != nil {
		tb.Fatal(err)
	}
	client.bind.conn = loopbackTransport{transport}
	client.init()
	return client
}

// The server lives in a separate process so its stack and encryption workers
// have an independent Go scheduler. Only the client's allocations are reported.
func TestWireGuardInboundBenchmarkProcess(t *testing.T) {
	if os.Getenv("YUH_INBOUND_BENCH_SERVER") != "1" {
		t.Skip("benchmark subprocess")
	}
	decoder := gob.NewDecoder(os.Stdin)
	var config ServerConfig
	if err := decoder.Decode(&config); err != nil {
		t.Fatal(err)
	}
	port, server := startInboundTestServer(t, config, inboundBenchmarkHandler{})
	if err := gob.NewEncoder(os.Stdout).Encode(port); err != nil {
		t.Fatal(err)
	}
	var stop bool
	_ = decoder.Decode(&stop)
	if err := gob.NewEncoder(os.Stdout).Encode(server.tunnel.Stack().Stats()); err != nil {
		t.Fatal(err)
	}
}

func benchmarkInboundClient(b *testing.B) *Wireguard {
	b.Helper()
	server, client := inboundTestConfigs(b)
	executable, err := os.Executable()
	if err != nil {
		b.Fatal(err)
	}
	cmd := exec.CommandContext(context.WithoutCancel(b.Context()), executable, "-test.run=^TestWireGuardInboundBenchmarkProcess$")
	cmd.Env = append(os.Environ(), "YUH_INBOUND_BENCH_SERVER=1", "GOMAXPROCS="+strconv.Itoa(runtime.GOMAXPROCS(0)))
	cmd.Stderr = os.Stderr
	input, err := cmd.StdinPipe()
	if err != nil {
		b.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		b.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		b.Fatal(err)
	}
	encoder, decoder := gob.NewEncoder(input), gob.NewDecoder(output)
	b.Cleanup(func() {
		if err := encoder.Encode(true); err != nil {
			b.Error(err)
		}
		var stats lightweight.Statistics
		if err := decoder.Decode(&stats); err != nil {
			b.Error(err)
		} else if b.N > 0 {
			b.ReportMetric(float64(stats.Drops)/float64(b.N), "server-drops/op")
			b.ReportMetric(float64(stats.Retransmissions)/float64(b.N), "server-retransmits/op")
		}
		_ = input.Close()
		if err := cmd.Wait(); err != nil {
			b.Error(err)
		}
	})
	if err := encoder.Encode(server); err != nil {
		b.Fatal(err)
	}
	var port int
	if err := decoder.Decode(&port); err != nil {
		b.Fatal(err)
	}
	return startInboundTestClient(b, client, port)
}

func BenchmarkWireGuardInboundUDP(b *testing.B) {
	for _, size := range []int{64, 1200} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			client := benchmarkInboundClient(b)
			socket, err := client.net.DialUDP(nil, nil)
			if err != nil {
				b.Fatal(err)
			}
			defer socket.Close()
			_ = socket.SetDeadline(time.Now().Add(time.Minute))
			dst := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("198.51.100.7:9000"))
			payload, reply := bytes.Repeat([]byte{0x5a}, size), make([]byte, size)
			exchange := func() {
				if _, err := socket.WriteTo(payload, dst); err != nil {
					b.Fatal(err)
				}
				if n, from, err := socket.ReadFrom(reply); err != nil || n != size || from.(*net.UDPAddr).AddrPort() != dst.AddrPort() || !bytes.Equal(payload, reply) {
					b.Fatalf("UDP echo: %d bytes from %v: %v", n, from, err)
				}
			}
			exchange() // Exclude handshake and lazy initialization.
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				exchange()
			}
		})
	}
}

func BenchmarkWireGuardInboundTCP(b *testing.B) {
	for _, mode := range []byte{'U', 'D'} {
		b.Run(string(mode), func(b *testing.B) {
			client := benchmarkInboundClient(b)
			socket, err := client.net.DialContextTCP(b.Context(), net.TCPAddrFromAddrPort(netip.MustParseAddrPort("198.51.100.7:9000")))
			if err != nil {
				b.Fatal(err)
			}
			defer socket.Close()
			_ = socket.SetDeadline(time.Now().Add(time.Minute))
			if _, err := socket.Write([]byte{mode}); err != nil {
				b.Fatal(err)
			}
			block, ack := bytes.Repeat([]byte{0x5a}, inboundBenchmarkBlock), []byte{mode}
			b.SetBytes(inboundBenchmarkBlock)
			b.ReportAllocs()
			for b.Loop() {
				if mode == 'U' {
					if _, err := socket.Write(block); err != nil {
						b.Fatal(err)
					}
					if _, err := io.ReadFull(socket, ack); err != nil {
						b.Fatal(err)
					}
				} else {
					if _, err := socket.Write(ack); err != nil {
						b.Fatal(err)
					}
					if _, err := io.ReadFull(socket, block); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}

func BenchmarkServerBindFromPeer(b *testing.B) {
	bind := newServerBind(conn.NewDefaultBind())
	endpoint, err := bind.Bind.ParseEndpoint("127.0.0.1:51820")
	if err != nil {
		b.Fatal(err)
	}
	received := &serverReceiveEndpoint{Endpoint: endpoint, owner: bind}
	key := [32]byte{1}
	b.ReportAllocs()
	for b.Loop() {
		received.FromPeer(key)
	}
}
