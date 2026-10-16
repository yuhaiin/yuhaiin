package lightweight

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"testing/synctest"
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
