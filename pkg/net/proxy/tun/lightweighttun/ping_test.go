package lightweighttun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight"
)

func pingWire(t *testing.T, src, dst netip.Addr) []byte {
	t.Helper()
	body := append([]byte{8, 0, 0, 0, 0x12, 0x34, 0xab, 0xcd}, []byte("deferred ping through handler")...)
	header := 20
	if src.Is6() {
		header = 40
		body[0] = 128
	}
	wire := make([]byte, header+len(body))
	if src.Is4() {
		wire[0], wire[8], wire[9] = 0x45, 64, 1
		binary.BigEndian.PutUint16(wire[2:4], uint16(len(wire)))
		a, b := src.As4(), dst.As4()
		copy(wire[12:16], a[:])
		copy(wire[16:20], b[:])
		binary.BigEndian.PutUint16(body[2:4], lightweight.Checksum(body))
		binary.BigEndian.PutUint16(wire[10:12], lightweight.Checksum(wire[:20]))
	} else {
		wire[0], wire[6], wire[7] = 0x60, 58, 64
		binary.BigEndian.PutUint16(wire[4:6], uint16(len(body)))
		a, b := src.As16(), dst.As16()
		copy(wire[8:24], a[:])
		copy(wire[24:40], b[:])
		pseudo := make([]byte, 40+len(body))
		copy(pseudo[:32], wire[8:40])
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(body)))
		pseudo[39] = 58
		copy(pseudo[40:], body)
		binary.BigEndian.PutUint16(body[2:4], lightweight.Checksum(pseudo))
	}
	copy(wire[header:], body)
	return wire
}
func TestPingRoutingPreparedButDisabled(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, mode := range []string{"default", "forward-success", "forward-failure", "local-interface", "local-prefix", "loopback", "foreign-source", "late-reply"} {
			name := "IPv4/" + mode
			if v6 {
				name = "IPv6/" + mode
			}
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					handler := netapi.NewChannelHandler(t.Context())
					options := &device.Opt{Handler: handler, Options: &netlink.Options{MTU: 1500, Inet4Address: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}, Inet6Address: []netip.Prefix{netip.MustParsePrefix("2001:db8::1/64")}}}
					config := stackConfig(options)
					if mode == "default" && config.ForwardPing {
						t.Fatal("production config enabled proxy ping")
					}
					if mode != "default" {
						config.ForwardPing = true
					}
					link := &udpTestLink{in: make(chan []byte, 8), out: make(chan []byte, 8), done: make(chan struct{}), once: new(sync.Once)}
					stack, err := lightweight.New(config, link)
					if err != nil {
						t.Fatal(err)
					}
					s := &server{stack: stack, options: options}
					if config.ForwardPing {
						for range pingWorkers {
							s.wg.Go(s.pingLoop)
						}
					}
					t.Cleanup(func() { _ = stack.Close(); s.wg.Wait() })
					src, dst := netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("203.0.113.9")
					if v6 {
						src, dst = netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("2001:db8:1::9")
					}
					switch mode {
					case "local-interface":
						dst = options.Inet4Address[0].Addr()
						if v6 {
							dst = options.Inet6Address[0].Addr()
						}
					case "local-prefix":
						dst = src.Next()
					case "loopback":
						dst = netip.MustParseAddr("127.0.0.1")
						if v6 {
							dst = netip.IPv6Loopback()
						}
					case "foreign-source":
						src = dst.Next()
					}
					wire := pingWire(t, src, dst)
					original, err := lightweight.ParsePacket(wire)
					if err != nil {
						t.Fatal(err)
					}
					link.in <- wire
					synctest.Wait()
					forwarded := mode == "forward-success" || mode == "forward-failure" || mode == "late-reply"
					if forwarded {
						select {
						case <-link.out:
							t.Fatal("echo returned before HandlePing result")
						default:
						}
						var meta *netapi.PingMeta
						select {
						case meta = <-handler.Ping():
						default:
							t.Fatal("request did not reach HandlePing")
						}
						if meta.Source.(netapi.IPAddress).AddrPort().Addr() != src || meta.Destination.(netapi.IPAddress).AddrPort().Addr() != dst {
							t.Fatal("incorrect ping routing metadata")
						}
						if mode == "late-reply" {
							if err := stack.Close(); err != nil {
								t.Fatal(err)
							}
							s.wg.Wait()
							if err := meta.WriteBack(0, nil); !errors.Is(err, net.ErrClosed) {
								t.Fatalf("late callback: %v", err)
							}
							select {
							case <-link.out:
								t.Fatal("closed adapter emitted a reply")
							default:
							}
							return
						}
						result := error(nil)
						if mode == "forward-failure" {
							result = errors.ErrUnsupported
						}
						if err := meta.WriteBack(123, result); err != nil {
							t.Fatal(err)
						}
						if err := meta.WriteBack(123, result); err != nil {
							t.Fatal(err)
						}
						synctest.Wait()
					} else {
						select {
						case <-handler.Ping():
							t.Fatal("default or local ping reached routing")
						default:
						}
					}
					var response lightweight.Packet
					select {
					case data := <-link.out:
						response, err = lightweight.ParsePacket(data)
						if err != nil {
							t.Fatal(err)
						}
					default:
						t.Fatal("missing ICMP response")
					}
					if response.Source != dst || response.Destination != src {
						t.Fatal("reply addresses changed")
					}
					if err := response.ValidateTransport(); err != nil {
						t.Fatal(err)
					}
					if mode == "forward-failure" {
						typ, code := byte(3), byte(1)
						if v6 {
							typ, code = 1, 3
						}
						if response.Payload[0] != typ || response.Payload[1] != code || !bytes.Equal(response.Payload[8:], wire) {
							t.Fatal("unsupported ping was not quoted as unreachable")
						}
					} else {
						typ := byte(0)
						if v6 {
							typ = 129
						}
						if response.Payload[0] != typ || !bytes.Equal(response.Payload[4:], original.Payload[4:]) {
							t.Fatal("echo identifier, sequence or payload changed")
						}
					}
					select {
					case <-link.out:
						t.Fatal("duplicate echo response")
					default:
					}
				})
			})
		}
	}
}
