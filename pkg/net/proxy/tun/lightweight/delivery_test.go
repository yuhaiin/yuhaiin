package lightweight

import (
	"encoding/binary"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight/congestion"
	"slices"
	"testing"
	"testing/synctest"
	"time"
)

func TestDeliverySACKCreditedOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, c, peer, seq := passiveWire(t, 100, 10000, "reno")
		if _, err := c.Write(make([]byte, 3*1460)); err != nil {
			t.Fatal(err)
		}
		for range 3 {
			_ = peerPacket(t, peer)
		}
		c.mu.Lock()
		initial := c.delivered
		c.mu.Unlock()
		sack := []byte{1, 1, 5, 10, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(sack[4:8], seq+1460)
		binary.BigEndian.PutUint32(sack[8:12], seq+3*1460)
		for range 2 {
			_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq, flagACK, 10000, sack, nil))
			synctest.Wait()
			c.mu.Lock()
			delivered := c.delivered
			c.mu.Unlock()
			if delivered-initial != 2*1460 {
				t.Fatalf("SACK credited %d bytes, want %d", delivered-initial, 2*1460)
			}
		}
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq+3*1460, flagACK, 10000, nil, nil))
		synctest.Wait()
		c.mu.Lock()
		delivered := c.delivered
		c.mu.Unlock()
		if delivered-initial != 3*1460 {
			t.Fatalf("cumulative ACK double-counted SACK: %d", delivered-initial)
		}
	})
}

type lossRecorder struct {
	*rateRecorder
	losses []congestion.LossEvent
}

func (r *lossRecorder) OnPacketLost(e congestion.LossEvent) { r.losses = append(r.losses, e) }
func TestDeliveryAfterRetransmissionAndSACK(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, c, peer, seq := passiveWire(t, 100, 10000, "reno")
		c.mu.Lock()
		recorder := &lossRecorder{rateRecorder: &rateRecorder{Controller: c.controller, window: 4 * 1460}}
		c.controller = recorder
		initial := c.delivered
		c.mu.Unlock()
		if _, err := c.Write(make([]byte, 4*1460)); err != nil {
			t.Fatal(err)
		}
		for range 4 {
			_ = peerPacket(t, peer)
		}
		sack := []byte{1, 1, 5, 10, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(sack[4:8], seq+1460)
		binary.BigEndian.PutUint32(sack[8:12], seq+4*1460)
		for range 3 {
			_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq, flagACK, 10000, sack, nil))
			synctest.Wait()
		}
		_ = peerPacket(t, peer)
		time.Sleep(10 * time.Millisecond)
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq+4*1460, flagACK, 10000, nil, nil))
		synctest.Wait()
		c.mu.Lock()
		event := recorder.last
		delivered, lost := c.delivered, c.lost
		losses := slices.Clone(recorder.losses)
		c.mu.Unlock()
		if delivered-initial != 4*1460 || lost != 1460 || len(losses) != 1 {
			t.Fatalf("delivery/loss accounting: delivered=%d lost=%d events=%d", delivered-initial, lost, len(losses))
		}
		if !event.RateSample || event.DeliveryRate == 0 || event.RTT != 0 || event.NewlyDelivered != 1460 {
			t.Fatalf("retransmitted sample lost rate or supplied ambiguous RTT: %+v", event)
		}
		if losses[0].SampleLost != 1460 || losses[0].TxInFlight == 0 {
			t.Fatalf("loss sampler missing original flight: %+v", losses[0])
		}
	})
}

func TestLateSACKCancelsPendingLossRepair(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, c, peer, seq := passiveWire(t, 100, 10000, "bbr")
		if _, err := c.Write(make([]byte, 8*1460)); err != nil {
			t.Fatal(err)
		}
		for range 8 {
			_ = peerPacket(t, peer)
		}
		sack := make([]byte, 28)
		sack[0], sack[1], sack[2], sack[3] = 1, 1, 5, 26
		for i, block := range [][2]int{{1, 2}, {3, 4}, {5, 8}} {
			binary.BigEndian.PutUint32(sack[4+8*i:], seq+uint32(block[0]*1460))
			binary.BigEndian.PutUint32(sack[8+8*i:], seq+uint32(block[1]*1460))
		}
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq, flagACK, 10000, sack, nil))
		_ = peerPacket(t, peer) // Only the first hole has bypassed the pacing wait.
		all := []byte{1, 1, 5, 10, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(all[4:8], seq+1460)
		binary.BigEndian.PutUint32(all[8:12], seq+8*1460)
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq, flagACK, 10000, all, nil))
		synctest.Wait()
		time.Sleep(100 * time.Millisecond)
		if s.Stats().Retransmissions != 1 {
			t.Fatal("late SACK failed to cancel queued retransmissions")
		}
	})
}
