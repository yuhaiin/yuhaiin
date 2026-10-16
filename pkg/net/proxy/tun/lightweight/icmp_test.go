package lightweight

import (
	"bytes"
	"encoding/binary"
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
func TestPMTURepeatedReductionRepairsCompleteFlight(t *testing.T) {
	for _, algorithm := range []string{"reno", "cubic", "bbr"} {
		t.Run(algorithm, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				_, c, peer, start := passiveWire(t, 0xfffffffe, 10000, algorithm)
				payload := make([]byte, 4380)
				for i := range payload {
					payload[i] = byte(i * 37)
				}
				if _, err := c.Write(payload); err != nil {
					t.Fatal(err)
				}
				// Caller storage must be independent of the retransmission views.
				want := bytes.Clone(payload)
				clear(payload)
				original := peerPacket(t, peer)
				for range 2 {
					_ = peerPacket(t, peer)
				}
				for _, mtu := range []int{1000, 600, 296} {
					now := time.Now()
					message := make([]byte, 36)
					message[0], message[1] = 3, 4
					binary.BigEndian.PutUint16(message[6:8], uint16(mtu))
					copy(message[8:], original.Data[:28])
					binary.BigEndian.PutUint16(message[2:4], Checksum(message))
					packet, err := makeIP(netip.MustParseAddr("192.0.2.254"), c.key.local.Addr(), 1, message, 1)
					if err != nil {
						t.Fatal(err)
					}
					_ = peer.WritePacket(packet)
					var got []byte
					for len(got) < len(want) {
						p := peerPacket(t, peer)
						if len(p.Data) > mtu {
							t.Fatalf("MTU %d: replacement length %d", mtu, len(p.Data))
						}
						if time.Since(now) >= time.Second {
							t.Fatal("PMTU replacement waited for RTO")
						}
						seq := binary.BigEndian.Uint32(p.Payload[4:8])
						if seq != start+uint32(len(got)) {
							t.Fatalf("MTU %d: sequence %x after %d bytes", mtu, seq, len(got))
						}
						h := int(p.Payload[12]>>4) * 4
						got = append(got, p.Payload[h:]...)
						original = p
					}
					if !bytes.Equal(got, want) {
						t.Fatal("PMTU replacement corrupted payload")
					}
					// The next quotation must refer to the beginning of an unACKed packet.
				}
				_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 0xffffffff, start+uint32(len(want)), flagACK, 10000, nil, nil))
				synctest.Wait()
				c.mu.Lock()
				remaining, nxt, una, rtt := c.tx.len(), c.sndNxt, c.sndUna, c.srtt
				c.mu.Unlock()
				if remaining != 0 || nxt != start+uint32(len(want)) || una != nxt {
					t.Fatal("PMTU ACK did not retire the complete original sequence range")
				}
				if rtt != 0 {
					t.Fatal("retransmitted PMTU data supplied an ambiguous RTT sample")
				}
			})
		})
	}
}
