package lightweight

import (
	"math"
	"testing"
	"testing/synctest"
)

func TestTCPSACKArrivalAndMergedRanges(t *testing.T) {
	for _, base := range []uint32{0, math.MaxUint32 - 25} {
		c := &TCPConn{sack: true}
		// Two adjacent pieces must produce one block, including across sequence wrap.
		for _, offset := range []uint32{10, 20, 40, 60, 80} {
			c.ooo = append(c.ooo, receivePiece{seq: base + offset, data: make([]byte, 10)})
		}
		for _, offset := range []uint32{80, 60, 40, 20, 20, 10} {
			c.rememberSACK(base + offset)
		}
		var buf [40]byte
		options, err := parseTCPOptions(c.headerOptions(buf[:], false))
		if err != nil || options.count != 4 {
			t.Fatalf("options=%+v err=%v", options, err)
		}
		want := []sackBlock{{base + 10, base + 30}, {base + 40, base + 50}, {base + 60, base + 70}, {base + 80, base + 90}}
		for i, block := range want {
			if options.blocks[i] != block {
				t.Fatalf("base=%d block=%d: %+v want %+v", base, i, options.blocks[i], block)
			}
		}
	}
}

// The first SACK block must describe the segment triggering the ACK, including
// when more disjoint ranges exist than fit in the TCP option area (RFC 2018).
func TestTCPSACKMostRecentBlock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, c, peer, ack := passiveWire(t, 100, 1000)
		for _, seq := range []uint32{201, 401, 601, 801, 1001} {
			if err := peer.WritePacket(wireTCP(c.key.remote, c.key.local,
				seq, ack, flagACK, 1000, nil, []byte{1})); err != nil {
				t.Fatal(err)
			}
			packet := peerPacket(t, peer)
			h := int(packet.Payload[12]>>4) * 4
			opts, err := parseTCPOptions(packet.Payload[20:h])
			if err != nil || opts.count == 0 {
				t.Fatalf("missing SACK: %+v, %v", opts, err)
			}
			if opts.blocks[0] != (sackBlock{seq, seq + 1}) {
				t.Errorf("trigger=%d first SACK=%+v; want [%d,%d)",
					seq, opts.blocks[0], seq, seq+1)
			}
			found := false
			for _, block := range opts.blocks[:opts.count] {
				found = found || block == (sackBlock{seq, seq + 1})
			}
			if !found {
				t.Errorf("newest segment [%d,%d) omitted from all %d SACK blocks", seq, seq+1, opts.count)
			}
		}
	})
}
