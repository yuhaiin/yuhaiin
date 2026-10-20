package lightweight

import (
	"encoding/binary"
	"fmt"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

func TestTCPMultipleHolesAfterRTO(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, c, peer, seq := passiveWire(t, 100, 10000, "reno")
		if _, err := c.Write(make([]byte, 4380)); err != nil {
			t.Fatal(err)
		}
		for range 3 {
			_ = peerPacket(t, peer)
		}
		time.Sleep(time.Second)
		_ = peerPacket(t, peer)
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq+1460, flagACK, 10000, nil, nil))
		now := time.Now()
		next := peerPacket(t, peer)
		if binary.BigEndian.Uint32(next.Payload[4:8]) != seq+1460 || !time.Now().Equal(now) {
			t.Fatal("RTO recovery waited for another RTO at the next hole")
		}
	})
}

func TestTCPKeepaliveResponsesAndTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, c, peer, seq := passiveConfigured(t, 100, 1000, Config{KeepaliveIdle: time.Second, KeepaliveInterval: time.Second, KeepaliveProbes: 2}, false)
		time.Sleep(time.Second)
		probe := peerPacket(t, peer)
		if binary.BigEndian.Uint32(probe.Payload[4:8]) != seq-1 {
			t.Fatal("invalid keepalive sequence")
		}
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq, flagACK, 1000, nil, nil))
		synctest.Wait()
		if c.State() != Established {
			t.Fatal("responsive keepalive closed connection")
		}
		for range 2 {
			time.Sleep(time.Second)
			_ = peerPacket(t, peer)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if c.State() != Closed || s.Stats().Connections != 0 {
			t.Fatal("unanswered keepalives retained flow")
		}
	})
}

func TestTCPSimultaneousClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := stackPair(t)
		l, err := b.ListenTCP(netip.MustParseAddrPort("192.0.2.2:80"))
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		client, err := a.DialContextTCP(t.Context(), netip.MustParseAddrPort("192.0.2.2:80"))
		if err != nil {
			t.Fatal(err)
		}
		server, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 2)
		go func() { done <- client.(interface{ CloseWrite() error }).CloseWrite() }()
		go func() { done <- server.(interface{ CloseWrite() error }).CloseWrite() }()
		for range 2 {
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		}
		for _, c := range []net.Conn{client, server} {
			if _, err := c.Read(make([]byte, 1)); err != io.EOF {
				t.Fatalf("simultaneous FIN: %v", err)
			}
		}
		synctest.Wait()
		for _, c := range []*TCPConn{client.(*TCPConn), server.(*TCPConn)} {
			if c.State() != TimeWait && c.State() != Closed {
				t.Fatalf("close stuck in %s", c.State())
			}
		}
	})
}

func TestTCPSACKAndFastRetransmit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, c, peer, seq := passiveWire(t, 100, 1000)
		if _, err := c.Write(make([]byte, 4380)); err != nil {
			t.Fatal(err)
		}
		for range 3 {
			_ = peerPacket(t, peer)
		}
		// An out-of-range SACK must not suppress retransmission of unACKed data.
		invalid := []byte{1, 1, 5, 10, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(invalid[4:8], seq-1)
		binary.BigEndian.PutUint32(invalid[8:12], seq+5000)
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq, flagACK, 1000, invalid, nil))
		synctest.Wait()
		valid := []byte{1, 1, 5, 10, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(valid[4:8], seq+1460)
		binary.BigEndian.PutUint32(valid[8:12], seq+4380)
		for range 2 {
			_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq, flagACK, 1000, valid, nil))
			synctest.Wait()
		}
		retrans := peerPacket(t, peer)
		if binary.BigEndian.Uint32(retrans.Payload[4:8]) != seq || c.stack.Stats().Retransmissions != 1 {
			t.Fatal("fast retransmit did not target the gap")
		}
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq+4380, flagACK, 1000, nil, nil))
		synctest.Wait()
		c.mu.Lock()
		remaining, recovering := c.tx.len(), c.recovering
		c.mu.Unlock()
		if remaining != 0 || recovering {
			t.Fatal("cumulative ACK failed to finish recovery")
		}
	})
}

func TestTCPTimeWaitAndDuplicateFIN(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, c, peer, seq := passiveWire(t, 100, 1000)
		if err := c.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		fin := peerPacket(t, peer)
		if fin.Payload[13]&flagFIN == 0 {
			t.Fatal("missing FIN")
		}
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq+1, flagACK|flagFIN, 1000, nil, nil))
		_ = peerPacket(t, peer)
		synctest.Wait()
		if c.State() != TimeWait {
			t.Fatal("missing TIME-WAIT")
		}
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq+1, flagACK|flagFIN, 1000, nil, nil))
		_ = peerPacket(t, peer)
		time.Sleep(s.config.TimeWait)
		synctest.Wait()
		if c.State() != Closed || s.Stats().Connections != 0 {
			t.Fatal("TIME-WAIT not reclaimed")
		}
	})
}

func TestTCPResetChallengeAndDeadlines(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, c, peer, seq := passiveWire(t, 100, 1000)
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 102, seq, flagRST, 1000, nil, nil))
		challenge := peerPacket(t, peer)
		if challenge.Payload[13]&flagACK == 0 || c.State() != Established {
			t.Fatal("in-window RST was not challenged")
		}
		_ = c.SetReadDeadline(time.Now().Add(time.Millisecond))
		_, err := c.Read(make([]byte, 1))
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("read deadline: %v", err)
		}
		_ = c.SetDeadline(time.Time{})
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq, flagRST, 1000, nil, nil))
		synctest.Wait()
		if c.State() != Closed {
			t.Fatal("exact reset did not close")
		}
		if _, err = c.Write([]byte{1}); !errors.Is(err, syscall.ECONNRESET) {
			t.Fatalf("reset write: %v", err)
		}
		_ = c.Close()
		if _, err = c.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closed read: %v", err)
		}
	})
}

func TestTCPSACKRepairsMultipleHolesInOneFlight(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, c, peer, seq := passiveWire(t, 100, 10000, "reno")
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
		now := time.Now()
		for range 3 {
			_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq, flagACK, 10000, sack, nil))
			synctest.Wait()
		}
		for _, index := range []int{0, 2, 4} {
			p := peerPacket(t, peer)
			if binary.BigEndian.Uint32(p.Payload[4:8]) != seq+uint32(index*1460) || !time.Now().Equal(now) {
				t.Fatal("SACK recovery serialized each loss behind another RTT/RTO")
			}
		}
	})
}

func TestTCPSACKRenegingRepairsRemainderWithoutAnotherRTO(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, c, peer, seq := passiveWire(t, 100, 10000, "reno")
		if _, err := c.Write(make([]byte, 3*1460)); err != nil {
			t.Fatal(err)
		}
		for range 3 {
			_ = peerPacket(t, peer)
		}
		sack := []byte{1, 1, 5, 10, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(sack[4:8], seq+1460)
		binary.BigEndian.PutUint32(sack[8:12], seq+3*1460)
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq, flagACK, 10000, sack, nil))
		synctest.Wait()
		time.Sleep(time.Second)
		_ = peerPacket(t, peer) // RTO retries the original cumulative hole.
		now := time.Now()
		// This ACK stops at data previously SACKed: the receiver has discarded it.
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq+1460, flagACK, 10000, nil, nil))
		for _, index := range []int{1, 2} {
			p := peerPacket(t, peer)
			if binary.BigEndian.Uint32(p.Payload[4:8]) != seq+uint32(index*1460) || time.Since(now) < 10*time.Millisecond || time.Since(now) >= time.Second {
				t.Fatal("SACK reneging did not repair the flight after a short ACK-reordering grace")
			}
		}
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq+3*1460, flagACK, 10000, nil, nil))
		synctest.Wait()
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.tx.len() != 0 || c.flight() != 0 || c.delivered != 1+3*1460 {
			t.Fatal("reneging corrupted flight or double-counted delivery")
		}
	})
}

func TestTCPSACKRepairsLostReplacementWithNewEvidence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, c, peer, seq := passiveWire(t, 100, 10000, "reno")
		if _, err := c.Write(make([]byte, 16*1460)); err != nil {
			t.Fatal(err)
		}
		for range 10 {
			_ = peerPacket(t, peer)
		}
		sack := []byte{1, 1, 5, 10, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(sack[4:8], seq+1460)
		binary.BigEndian.PutUint32(sack[8:12], seq+10*1460)
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq, flagACK, 10000, sack, nil))
		_ = peerPacket(t, peer) // First repair is lost too.
		for received := 0; received < 6*1460; {
			p := peerPacket(t, peer)
			if binary.BigEndian.Uint32(p.Payload[4:8]) != seq+10*1460+uint32(received) {
				t.Fatal("unexpected new-data sequence during recovery")
			}
			received += len(p.Payload) - int(p.Payload[12]>>4)*4
		}
		now := time.Now()
		binary.BigEndian.PutUint32(sack[8:12], seq+16*1460)
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq, flagACK, 10000, sack, nil))
		// Let the receive and output goroutines process the new SACK without
		// letting synctest advance its fake clock to the retransmission timeout.
		// peerPacket waits with a 1s timer, exactly the initial RTO, and can
		// accidentally observe the RTO retransmission instead of fast recovery.
		synctest.Wait()
		select {
		case raw := <-peer.rx:
			repair, err := ParsePacket(raw)
			if err != nil {
				t.Fatal(err)
			}
			gotSeq := binary.BigEndian.Uint32(repair.Payload[4:8])
			gotRetrans := s.Stats().Retransmissions
			if !time.Now().Equal(now) || gotSeq != seq || gotRetrans != 2 {
				t.Fatalf("new SACK repair: seq=%d want=%d retransmissions=%d want=2 elapsed=%v",
					gotSeq, seq, gotRetrans, time.Since(now))
			}
		default:
			c.mu.Lock()
			flight, cwnd := c.flight(), c.controller.CongestionWindow()
			repairPending, recovering := c.repairPending, c.recovering
			var txHead string
			if c.tx.len() > 0 {
				v := c.tx.values()[0]
				txHead = fmt.Sprintf("seq=%d sent=%d sacked=%t lost=%t retransmitEnd=%d",
					v.seq, v.transmissions, v.sacked, v.lossReported, v.retransmitEnd)
			}
			c.mu.Unlock()
			t.Fatalf("new SACK did not trigger immediate repair: retransmissions=%d flight=%d cwnd=%d repairPending=%t recovering=%t head={%s}",
				s.Stats().Retransmissions, flight, cwnd, repairPending, recovering, txHead)
		}
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq+16*1460, flagACK, 10000, nil, nil))
		synctest.Wait()
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.flight() != 0 || c.tx.len() != 0 || c.delivered != 1+16*1460 {
			t.Fatal("repaired replacement corrupted delivery accounting")
		}
	})
}

func TestReorderedACKDoesNotDeclareSACKReneging(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, c, peer, seq := passiveWire(t, 100, 10000, "reno")
		if _, err := c.Write(make([]byte, 3*1460)); err != nil {
			t.Fatal(err)
		}
		for range 3 {
			_ = peerPacket(t, peer)
		}
		sack := []byte{1, 1, 5, 10, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(sack[4:8], seq+1460)
		binary.BigEndian.PutUint32(sack[8:12], seq+3*1460)
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq, flagACK, 10000, sack, nil))
		// This advancing ACK was generated before the SACK above, but reordered.
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq+1460, flagACK, 10000, nil, nil))
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq+3*1460, flagACK, 10000, nil, nil))
		synctest.Wait()
		time.Sleep(20 * time.Millisecond)
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.lost != 0 || s.Stats().Retransmissions != 0 || c.flight() != 0 {
			t.Fatal("reordered cumulative ACK caused spurious SACK-reneging recovery")
		}
	})
}
