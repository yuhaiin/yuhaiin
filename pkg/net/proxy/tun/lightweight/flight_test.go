package lightweight

import (
	"encoding/binary"
	"testing"
	"testing/synctest"
)

func TestTCPFlightACKSACKAndPartialACK(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, c, peer, seq := passiveWire(t, 100, 10000)
		const mss = 1460
		if _, err := c.Write(make([]byte, 3*mss)); err != nil {
			t.Fatal(err)
		}
		for range 3 {
			_ = peerPacket(t, peer)
		}
		check := func(want uint64) {
			t.Helper()
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.flight() != want {
				t.Fatalf("flight=%d want=%d", c.flight(), want)
			}
		}
		check(3 * mss)
		sack := []byte{1, 1, 5, 10, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(sack[4:8], seq+mss)
		binary.BigEndian.PutUint32(sack[8:12], seq+3*mss)
		for range 2 { // Repeated SACK cannot deduct the same bytes twice.
			_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq, flagACK, 10000, sack, nil))
			synctest.Wait()
			check(mss)
		}
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq+100, flagACK, 10000, sack, nil))
		synctest.Wait()
		check(mss - 100)
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq+3*mss, flagACK, 10000, nil, nil))
		synctest.Wait()
		check(0) // Cumulative ACK retires the already-delivered SACK ranges once.

	})
}
