package lightweight

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
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
		if _, err = c.Write([]byte{1}); err == nil {
			t.Fatal("reset write succeeded")
		}
		_ = c.Close()
		if _, err = c.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closed read: %v", err)
		}
	})
}
