package lightweight

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"
)

func wireTCP(src, dst netip.AddrPort, seq, ack uint32, flags byte, window uint16, options, data []byte) []byte {
	h := 20 + len(options)
	b := make([]byte, h+len(data))
	binary.BigEndian.PutUint16(b[:2], src.Port())
	binary.BigEndian.PutUint16(b[2:4], dst.Port())
	binary.BigEndian.PutUint32(b[4:8], seq)
	binary.BigEndian.PutUint32(b[8:12], ack)
	b[12] = byte(h/4) << 4
	b[13] = flags
	binary.BigEndian.PutUint16(b[14:16], window)
	copy(b[20:], options)
	copy(b[h:], data)
	binary.BigEndian.PutUint16(b[16:18], transportChecksum(src.Addr(), dst.Addr(), 6, b))
	out, err := makeIP(src.Addr(), dst.Addr(), 6, b, 1)
	if err != nil {
		panic(err)
	}
	return out
}
func peerPacket(t *testing.T, m *memoryIO) Packet {
	t.Helper()
	select {
	case b := <-m.rx:
		p, err := ParsePacket(b)
		if err != nil {
			t.Fatal(err)
		}
		return p
	case <-time.After(time.Second):
		t.Fatal("peer packet timed out")
		return Packet{}
	}
}
func passiveWire(t *testing.T, isn uint32, window uint16, algorithms ...string) (*Stack, *TCPConn, *memoryIO, uint32) {
	t.Helper()
	algorithm := "cubic"
	if len(algorithms) > 0 {
		algorithm = algorithms[0]
	}
	return passiveConfigured(t, isn, window, Config{CongestionControl: algorithm}, false)
}
func passiveConfigured(t *testing.T, isn uint32, window uint16, cfg Config, unbuffered bool) (*Stack, *TCPConn, *memoryIO, uint32) {
	return passiveConfiguredFamily(t, isn, window, cfg, unbuffered, false)
}
func passiveConfiguredFamily(t *testing.T, isn uint32, window uint16, cfg Config, unbuffered, ipv6 bool) (*Stack, *TCPConn, *memoryIO, uint32) {
	t.Helper()
	a, b := memoryPair()
	if unbuffered {
		ch := make(chan []byte)
		a.tx = ch
		b.rx = ch
	}
	localAddr, remoteAddr := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	if ipv6 {
		localAddr = netip.MustParseAddr("2001:db8::1")
		remoteAddr = netip.MustParseAddr("2001:db8::2")
	}
	cfg.Addresses = []netip.Addr{localAddr}
	s, err := New(cfg, a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	local, remote := netip.AddrPortFrom(localAddr, 80), netip.AddrPortFrom(remoteAddr, 40000)
	l, err := s.ListenTCP(local)
	if err != nil {
		t.Fatal(err)
	}
	mss := s.config.MTU - 40
	if ipv6 {
		mss -= 20
	}
	_ = b.WritePacket(wireTCP(remote, local, isn, 0, flagSYN, window, []byte{2, 4, byte(mss >> 8), byte(mss), 4, 2, 3, 3, 3, 1, 1, 1}, nil))
	synack := peerPacket(t, b)
	serverISN := binary.BigEndian.Uint32(synack.Payload[4:8])
	_ = b.WritePacket(wireTCP(remote, local, isn+1, serverISN+1, flagACK, window, nil, nil))
	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	return s, conn.(*TCPConn), b, serverISN + 1
}

func TestBBRActuallyPacesPackets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gaps := map[string]time.Duration{}
		for _, algorithm := range []string{"reno", "cubic", "bbr"} {
			s, c, peer, _ := passiveWire(t, 100, 10000, algorithm)
			if _, err := c.Write(make([]byte, 4*1460)); err != nil {
				t.Fatal(err)
			}
			_ = peerPacket(t, peer)
			first := time.Now()
			_ = peerPacket(t, peer)
			gaps[algorithm] = time.Since(first)
			_ = s.Close()
		}
		if gaps["bbr"] <= 0 || gaps["reno"] != 0 || gaps["cubic"] != 0 {
			t.Fatalf("actual wire spacing: %+v", gaps)
		}
	})
}

func TestTCPCloseInterruptsBlockedIO(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, c, _, _ := passiveWire(t, 100, 0)
		read, write := make(chan error, 1), make(chan error, 1)
		go func() { _, err := c.Read(make([]byte, 1)); read <- err }()
		go func() {
			n, err := c.Write(make([]byte, s.config.SendBuffer+1))
			if n != s.config.SendBuffer {
				write <- fmt.Errorf("partial write %d", n)
				return
			}
			write <- err
		}()
		synctest.Wait()
		_ = c.Close()
		synctest.Wait()
		for _, ch := range []chan error{read, write} {
			if err := <-ch; !errors.Is(err, net.ErrClosed) {
				t.Fatalf("blocked operation: %v", err)
			}
		}
	})
}

func TestTCPInitialWindowSequenceWrap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for _, isn := range []uint32{1, 0x80000000, 0xf0000000, 0xfffffffe} {
			_, c, peer, serverSeq := passiveWire(t, isn, 100)
			if _, err := c.Write(make([]byte, 2000)); err != nil {
				t.Fatal(err)
			}
			packet := peerPacket(t, peer)
			h := int(packet.Payload[12]>>4) * 4
			if len(packet.Payload)-h != 800 {
				t.Fatalf("ISN %x: sent %d bytes beyond negotiated 800 byte window", isn, len(packet.Payload)-h)
			}
			_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, isn+1, serverSeq+800, flagACK, 100, nil, nil))
			synctest.Wait()
			if c.stack.Stats().Drops != 0 {
				t.Fatal("unexpected drop")
			}
			_ = c.Close()
			_ = c.stack.Close()
		}
	})
}

func TestTCPKarnAmbiguousCumulativeACK(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, c, peer, seq := passiveWire(t, 100, 1000)
		c.mu.Lock()
		beforeRTT := c.srtt
		c.mu.Unlock()
		if _, err := c.Write(make([]byte, 2920)); err != nil {
			t.Fatal(err)
		}
		_ = peerPacket(t, peer)
		_ = peerPacket(t, peer)
		time.Sleep(1100 * time.Millisecond)
		_ = peerPacket(t, peer)
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq+2920, flagACK, 1000, nil, nil))
		synctest.Wait()
		c.mu.Lock()
		afterRTT := c.srtt
		c.mu.Unlock()
		if afterRTT != beforeRTT {
			t.Fatalf("ambiguous cumulative ACK changed RTT: %v -> %v", beforeRTT, afterRTT)
		}
	})
}

func TestTCPZeroWindowReopen(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, c, peer, seq := passiveWire(t, 100, 0)
		if _, err := c.Write([]byte("blocked")); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		select {
		case <-peer.rx:
			t.Fatal("data sent into zero window")
		default:
		}
		time.Sleep(time.Second)
		probe := peerPacket(t, peer)
		if binary.BigEndian.Uint32(probe.Payload[4:8]) != seq-1 || len(probe.Payload) != 20 {
			t.Fatal("persist probe consumed new sequence space")
		}
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq, flagACK, 1000, nil, nil))
		packet := peerPacket(t, peer)
		if string(packet.Payload[int(packet.Payload[12]>>4)*4:]) != "blocked" {
			t.Fatal("window reopening did not resume")
		}
	})
}

func TestTCPReceiveOverlapWrapAndFIN(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, c, peer, serverSeq := passiveWire(t, 0xfffffffc, 1000)
		send := func(seq uint32, flags byte, payload string) {
			_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, seq, serverSeq, flags, 1000, nil, []byte(payload)))
			synctest.Wait()
		}
		send(0, flagACK, "DEF")
		send(0xffffffff, flagACK, "cXX")
		send(0xfffffffd, flagACK, "ab")
		buf := make([]byte, 6)
		n, err := c.Read(buf)
		if err != nil || n != 6 || string(buf) != "abcDEF" {
			t.Fatalf("first arrival overlap/wrap: %q %v", buf[:n], err)
		}
		send(3, flagACK|flagFIN, "")
		if _, err = c.Read(buf); err != io.EOF {
			t.Fatalf("FIN: %v", err)
		}
	})
}

func TestTCPBoundedOutputBackpressure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, c, peer, seq := passiveConfigured(t, 100, 10000, Config{QueuePackets: 2}, true)
		if _, err := c.Write(make([]byte, 14600)); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		started := time.Now()
		received := uint32(0)
		for received < 14600 {
			p := peerPacket(t, peer)
			h := int(p.Payload[12]>>4) * 4
			n := len(p.Payload) - h
			if n == 0 {
				continue
			}
			packetSeq := binary.BigEndian.Uint32(p.Payload[4:8])
			if packetSeq != seq+received {
				t.Fatal("output reordered or duplicated")
			}
			received += uint32(n)
			_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq+received, flagACK, 10000, nil, nil))
		}
		if time.Since(started) >= time.Second || s.Stats().Retransmissions != 0 {
			t.Fatalf("queue admission was treated as packet loss: %v %+v", time.Since(started), s.Stats())
		}
	})
}

func TestTCPScaledWindowKeepsPreviouslyAdvertisedBytes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, c, peer, seq := passiveWire(t, 100, 10000)
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq, flagACK, 10000, nil, make([]byte, 1000)))
		time.Sleep(20 * time.Millisecond)
		_ = peerPacket(t, peer)
		// The SYN-ACK offered 65535 bytes. Rounding a subsequent scaled window down
		// must not revoke acceptance of any of those previously offered bytes.
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 1101, seq, flagACK, 10000, nil, make([]byte, 64535)))
		synctest.Wait()
		_ = c.SetReadDeadline(time.Now().Add(time.Millisecond))
		n, err := io.ReadFull(c, make([]byte, 65535))
		if err != nil || n != 65535 {
			t.Fatalf("scaled window revoked previously offered bytes: %d %v", n, err)
		}
	})
}
