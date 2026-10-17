package lightweight

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"testing/synctest"
)

func wirePing(t *testing.T, src, dst netip.Addr) []byte {
	t.Helper()
	msg := append([]byte{8, 0, 0, 0, 0x12, 0x34, 0xab, 0xcd}, []byte("owned echo payload")...)
	proto := byte(1)
	if src.Is6() {
		proto = 58
		msg[0] = 128
	}
	sum := Checksum(msg)
	if proto == 58 {
		sum = transportChecksum(src, dst, proto, msg)
	}
	binary.BigEndian.PutUint16(msg[2:4], sum)
	wire, err := makeIP(src, dst, proto, msg, 123)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
func TestForwardPingReply(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, failed := range []bool{false, true} {
			name := "IPv4"
			if v6 {
				name = "IPv6"
			}
			if failed {
				name += "/failure"
			} else {
				name += "/success"
			}
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					link, peer := memoryPair()
					s, err := New(Config{Promiscuous: true, ForwardPing: true}, link)
					if err != nil {
						t.Fatal(err)
					}
					defer s.Close()
					src, dst := netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("203.0.113.9")
					if v6 {
						src, dst = netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("2001:db8:1::9")
					}
					wire := wirePing(t, src, dst)
					original := bytes.Clone(wire)
					if err := s.input(wire); err != nil {
						t.Fatal(err)
					}
					clear(wire) // A TUN reader reuses this buffer as soon as input returns.
					synctest.Wait()
					select {
					case <-peer.rx:
						t.Fatal("Echo was answered before the upstream result")
					default:
					}
					request, err := s.ReceivePing(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					if request.Source != src || request.Destination != dst {
						t.Fatal("incorrect ping endpoints")
					}
					if s.Stats().MemoryBytes != 0 {
						t.Fatal("handoff did not release queue accounting")
					}
					result := error(nil)
					if failed {
						result = errors.ErrUnsupported
					}
					var wg sync.WaitGroup
					for range 2 {
						wg.Go(func() {
							if err := request.Reply(result); err != nil {
								t.Error(err)
							}
						})
					}
					wg.Wait()
					synctest.Wait()
					response := peerPacket(t, peer)
					if response.Source != dst || response.Destination != src {
						t.Fatal("incorrect reply direction")
					}
					if err := response.ValidateTransport(); err != nil {
						t.Fatal(err)
					}
					if failed {
						typ, code := byte(3), byte(1)
						if v6 {
							typ, code = 1, 3
						}
						if response.Payload[0] != typ || response.Payload[1] != code || !bytes.Equal(response.Payload[8:], original) {
							t.Fatal("error was not a quoted Destination Unreachable")
						}
					} else {
						originalPacket, err := ParsePacket(original)
						if err != nil {
							t.Fatal(err)
						}
						typ := byte(0)
						if v6 {
							typ = 129
						}
						if response.Payload[0] != typ || !bytes.Equal(response.Payload[4:], originalPacket.Payload[4:]) {
							t.Fatal("echo ID, sequence or payload changed")
						}
					}
					select {
					case <-peer.rx:
						t.Fatal("duplicate callback emitted another response")
					default:
					}
				})
			})
		}
	}
}
func TestForwardPingBoundsAndClose(t *testing.T) {
	if reflect.TypeFor[PingRequest]().Size() > pingCharge {
		t.Fatal("ping metadata exceeds accounting")
	}
	link, _ := memoryPair()
	s, err := New(Config{Promiscuous: true, ForwardPing: true, QueuePackets: 1}, link)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	wire := wirePing(t, netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("203.0.113.9"))
	for range 2 {
		if err := s.input(wire); err != nil {
			t.Fatal(err)
		}
	}
	if s.Stats().Drops != 1 || s.Stats().MemoryBytes != int64(len(wire)+pingCharge) {
		t.Fatalf("unbounded ping queue: %+v", s.Stats())
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if s.Stats().MemoryBytes != 0 {
		t.Fatal("queued request retained after Close")
	}
	if _, err := s.ReceivePing(t.Context()); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}
func TestForwardPingCancellationAndLateReply(t *testing.T) {
	link, _ := memoryPair()
	s, err := New(Config{Promiscuous: true, ForwardPing: true}, link)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.ReceivePing(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	wire := wirePing(t, netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("203.0.113.9"))
	if err := s.input(wire); err != nil {
		t.Fatal(err)
	}
	request, err := s.ReceivePing(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := request.Reply(nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("reply after Close: %v", err)
	}
}

func TestForwardPingMemoryBudgetAndBlockedReceiver(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		link, _ := memoryPair()
		s, err := New(Config{Promiscuous: true, ForwardPing: true, MemoryLimit: 1 << 20}, link)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		src, dst := netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("203.0.113.9")
		packet, err := ParsePacket(wirePing(t, src, dst))
		if err != nil {
			t.Fatal(err)
		}
		message := append(bytes.Clone(packet.Payload), make([]byte, 60000)...)
		message[2], message[3] = 0, 0
		binary.BigEndian.PutUint16(message[2:4], Checksum(message))
		wire, err := makeIP(src, dst, 1, message, 1)
		if err != nil {
			t.Fatal(err)
		}
		for range 32 {
			if err := s.input(wire); err != nil {
				t.Fatal(err)
			}
		}
		if st := s.Stats(); st.MemoryBytes > 1<<20 || st.Drops == 0 {
			t.Fatalf("ping memory budget: %+v", st)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if s.Stats().MemoryBytes != 0 {
			t.Fatal("memory retained after Close")
		}
	})
	synctest.Test(t, func(t *testing.T) {
		link, _ := memoryPair()
		s, err := New(Config{ForwardPing: true}, link)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		done := make(chan error, 1)
		go func() { _, err := s.ReceivePing(t.Context()); done <- err }()
		synctest.Wait()
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-done; !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	})
}
