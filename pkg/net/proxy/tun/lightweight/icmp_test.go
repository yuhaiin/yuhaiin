package lightweight

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"
)

func TestICMPQuotedPMTUReducesTCPPacketSize(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, c, peer, _ := passiveWire(t, 100, 10000)
		if _, err := c.Write(make([]byte, 1460)); err != nil {
			t.Fatal(err)
		}
		original := peerPacket(t, peer)
		message := make([]byte, 8+28)
		message[0] = 3
		message[1] = 4
		binary.BigEndian.PutUint16(message[6:8], 1000)
		copy(message[8:], original.Data[:28])
		binary.BigEndian.PutUint16(message[2:4], Checksum(message))
		packet, err := makeIP(netip.MustParseAddr("192.0.2.254"), c.key.local.Addr(), 1, message, 1)
		if err != nil {
			t.Fatal(err)
		}
		_ = peer.WritePacket(packet)
		retransmission := peerPacket(t, peer)
		if len(retransmission.Data) > 1000 || retransmission.Protocol != 6 || len(retransmission.Payload) <= 20 {
			t.Fatalf("PMTU retransmission length %d", len(retransmission.Data))
		}
	})
}

// Every replacement must be emitted before the RTO, including the second and
// later pieces of an old packet. Repeating the PMTU reduction while the flight
// is unacknowledged must preserve sequence space, payload and Karn history.
// pmtuTestReply models a router's minimal quotation, including the complete
// IPv6 header plus the transport tuple/sequence. It borrows no packet storage.
func pmtuTestReply(original Packet, mtu int) ([]byte, error) {
	router := netip.MustParseAddr("192.0.2.254")
	proto := byte(1)
	quote := len(original.Data) - len(original.Payload) + 8
	message := make([]byte, 8+quote)
	message[0], message[1] = 3, 4
	binary.BigEndian.PutUint16(message[6:8], uint16(mtu))
	if original.Source.Is6() {
		router = netip.MustParseAddr("2001:db8::fe")
		proto = 58
		message[0], message[1] = 2, 0
		binary.BigEndian.PutUint32(message[4:8], uint32(mtu))
	}
	copy(message[8:], original.Data[:quote])
	sum := Checksum(message)
	if proto == 58 {
		sum = transportChecksum(router, original.Source, 58, message)
	}
	binary.BigEndian.PutUint16(message[2:4], sum)
	return makeIP(router, original.Source, proto, message, 1)
}
func TestPMTURepeatedReductionRepairsCompleteFlight(t *testing.T) {
	for _, algorithm := range []string{"reno", "cubic", "bbr"} {
		for _, ipv6 := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/ipv6=%t", algorithm, ipv6), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					mtu := 1500
					limits := []int{1000, 600, 296}
					if ipv6 {
						mtu = 9000
						limits = []int{4000, 2000, 1280}
					}
					_, c, peer, start := passiveConfiguredFamily(t, 0xfffffffe, 10000, Config{MTU: mtu, CongestionControl: algorithm}, false, ipv6)
					payload := make([]byte, min(3*c.mss, int(c.controller.CongestionWindow())))
					for i := range payload {
						payload[i] = byte(i * 37)
					}
					if _, err := c.Write(payload); err != nil {
						t.Fatal(err)
					}
					want := bytes.Clone(payload)
					clear(payload)
					var original Packet
					for sent := 0; sent < len(want); {
						original = peerPacket(t, peer)
						sent += len(original.Payload) - int(original.Payload[12]>>4)*4
					}
					for _, limit := range limits {
						now := time.Now()
						packet, err := pmtuTestReply(original, limit)
						if err != nil {
							t.Fatal(err)
						}
						_ = peer.WritePacket(packet)
						var got []byte
						for len(got) < len(want) {
							p := peerPacket(t, peer)
							if len(p.Data) > limit {
								t.Fatalf("MTU %d: replacement length %d", limit, len(p.Data))
							}
							if time.Since(now) >= time.Second {
								t.Fatal("PMTU replacement waited for RTO")
							}
							seq := binary.BigEndian.Uint32(p.Payload[4:8])
							if seq != start+uint32(len(got)) {
								t.Fatalf("MTU %d: sequence %x after %d bytes", limit, seq, len(got))
							}
							got = append(got, p.Payload[int(p.Payload[12]>>4)*4:]...)
							original = p
						}
						if !bytes.Equal(got, want) {
							t.Fatal("PMTU replacement corrupted payload")
						}
					}
					_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 0xffffffff, start+uint32(len(want)), flagACK, 10000, nil, nil))
					synctest.Wait()
					c.mu.Lock()
					defer c.mu.Unlock()
					if c.tx.len() != 0 || c.sndNxt != start+uint32(len(want)) || c.sndUna != c.sndNxt {
						t.Fatal("PMTU ACK did not retire original sequence space")
					}
					if c.lost != 0 {
						t.Fatal("PMTU replacement counted as network loss")
					}
					if c.srtt != 0 {
						t.Fatal("PMTU retransmission supplied ambiguous RTT")
					}
				})
			})
		}
	}
}
