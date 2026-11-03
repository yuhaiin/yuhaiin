package lightweight

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"
)

func sackOptions(blocks ...sackBlock) []byte {
	b := make([]byte, 4+8*len(blocks))
	b[0], b[1], b[2], b[3] = 1, 1, 5, byte(2+8*len(blocks))
	for i, block := range blocks {
		binary.BigEndian.PutUint32(b[4+8*i:], block.start)
		binary.BigEndian.PutUint32(b[8+8*i:], block.end)
	}
	return b
}

func seedRecoveryRTT(t *testing.T, c *TCPConn, peer *memoryIO, seq uint32) uint32 {
	t.Helper()
	if _, err := c.Write([]byte("seed")); err != nil {
		t.Fatal(err)
	}
	_ = peerPacket(t, peer)
	time.Sleep(10 * time.Millisecond)
	seq += 4
	_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq, flagACK, 10000, nil, nil))
	synctest.Wait()
	return seq
}

func TestRACKWireRecoversSmallFlight(t *testing.T) {
	for _, algorithm := range []string{"reno", "cubic", "bbr"} {
		for _, ipv6 := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/ipv6=%v", algorithm, ipv6), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					_, c, peer, seq := passiveConfiguredFamily(t, 100, 10000, Config{CongestionControl: algorithm, LossRecovery: "rack-tlp"}, false, ipv6)
					seq = seedRecoveryRTT(t, c, peer, seq)
					mss := uint32(c.mss)
					if _, err := c.Write(make([]byte, 3*int(mss))); err != nil {
						t.Fatal(err)
					}
					for range 3 {
						_ = peerPacket(t, peer)
					}
					time.Sleep(10 * time.Millisecond)
					start := time.Now()
					_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq, flagACK, 10000,
						sackOptions(sackBlock{seq + mss, seq + 3*mss}), nil))
					p := peerPacket(t, peer)
					if binary.BigEndian.Uint32(p.Payload[4:8]) != seq || time.Since(start) >= 100*time.Millisecond {
						t.Fatal("small flight waited for RTO or retransmitted the wrong hole")
					}
					_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq+3*mss, flagACK, 10000, nil, nil))
					synctest.Wait()
					d := c.DiagnosticSnapshot()
					if d.BytesInFlight != 0 || d.SendQueueBytes != 0 || d.Retransmissions != 1 || d.LossRecovery != "rack-tlp" {
						t.Fatalf("invalid recovery accounting: %+v", d)
					}
				})
			})
		}
	}
}

func TestTLPWireRetransmitsTailAndFallsBackToRTO(t *testing.T) {
	for _, algorithm := range []string{"reno", "cubic", "bbr"} {
		t.Run(algorithm, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				_, c, peer, seq := passiveConfigured(t, 100, 10000, Config{CongestionControl: algorithm, LossRecovery: "rack-tlp"}, false)
				seq = seedRecoveryRTT(t, c, peer, seq)
				if _, err := c.Write(make([]byte, 2*c.mss)); err != nil {
					t.Fatal(err)
				}
				for range 2 {
					_ = peerPacket(t, peer)
				}
				start := time.Now()
				probe := peerPacket(t, peer)
				if binary.BigEndian.Uint32(probe.Payload[4:8]) != seq+uint32(c.mss) || time.Since(start) >= time.Second {
					t.Fatal("TLP did not probe the tail before RTO")
				}
				d := c.DiagnosticSnapshot()
				if d.TailLossProbes != 1 || d.LostBytes != 0 || d.BytesInFlight != uint64(2*c.mss) {
					t.Fatalf("probe changed loss/flight accounting: %+v", d)
				}
				// Lose the probe as well. The next retransmission must be the RTO head.
				time.Sleep(time.Second)
				synctest.Wait()
				next := peerPacket(t, peer)
				if binary.BigEndian.Uint32(next.Payload[4:8]) != seq || c.DiagnosticSnapshot().TailLossProbes != 1 {
					t.Fatal("failed probe looped instead of entering RTO")
				}
			})
		})
	}
}

func TestDSACKWireBelowAndAboveCumulativeACK(t *testing.T) {
	for _, offset := range []uint32{0, 100} {
		t.Run(fmt.Sprint(offset), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				_, c, peer, seq := passiveWire(t, 100, 10000)
				dataSeq := uint32(101) + offset
				data := []byte("duplicate")
				packet := wireTCP(c.key.remote, c.key.local, dataSeq, seq, flagACK, 10000, nil, data)
				_ = peer.WritePacket(packet)
				_ = peerPacket(t, peer)
				_ = peer.WritePacket(packet)
				p := peerPacket(t, peer)
				h := int(p.Payload[12]>>4) * 4
				o, err := parseTCPOptions(p.Payload[20:h])
				if err != nil || o.count == 0 || o.blocks[0] != (sackBlock{dataSeq, dataSeq + uint32(len(data))}) {
					t.Fatalf("missing duplicate range: %+v %v", o, err)
				}
				if offset > 0 && (o.count < 2 || o.blocks[0] != o.blocks[1]) {
					t.Fatal("above-ACK DSACK omitted enclosing SACK")
				}
				if c.DiagnosticSnapshot().DSACKSent != 1 {
					t.Fatal("duplicate feedback was not counted")
				}
			})
		})
	}
}

func TestDSACKDoesNotInvalidateOrdinarySACK(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, c, peer, seq := passiveWire(t, 100, 10000)
		if _, err := c.Write(make([]byte, 4*c.mss)); err != nil {
			t.Fatal(err)
		}
		for range 4 {
			_ = peerPacket(t, peer)
		}
		end := seq + uint32(4*c.mss)
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq, flagACK, 10000,
			sackOptions(sackBlock{seq - 10, seq}, sackBlock{seq + uint32(c.mss), end}), nil))
		p := peerPacket(t, peer)
		if binary.BigEndian.Uint32(p.Payload[4:8]) != seq {
			t.Fatal("DSACK discarded valid loss evidence")
		}
		if c.DiagnosticSnapshot().DSACKReceived != 1 {
			t.Fatal("DSACK not classified separately")
		}
	})
}

func TestDSACKUndoRequiresEveryLoss(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, c, _, _ := passiveWire(t, 100, 10000, "bbr")
		c.mu.Lock()
		defer c.mu.Unlock()
		c.beginRecovery(time.Now())
		c.undoRanges[0], c.undoRanges[1] = sackBlock{100, 200}, sackBlock{200, 300}
		c.undoCount, c.recover, c.sndUna = 2, 300, 300
		c.proveSpurious(sackBlock{100, 200}, time.Now())
		if c.spuriousRecoveries != 0 {
			t.Fatal("partial DSACK undid genuine losses")
		}
		c.proveSpurious(sackBlock{200, 300}, time.Now())
		if c.spuriousRecoveries != 1 {
			t.Fatal("complete conservative proof did not reach BBR")
		}
		c.proveSpurious(sackBlock{200, 300}, time.Now())
		if c.spuriousRecoveries != 1 {
			t.Fatal("replayed DSACK undid recovery twice")
		}
	})
}

func TestRACKWireSACKNegotiationFallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, c, peer, seq := passiveConfiguredFamily(t, 100, 10000, Config{LossRecovery: "rack-tlp"}, false, false, false)
		if _, err := c.Write([]byte("fallback")); err != nil {
			t.Fatal(err)
		}
		_ = peerPacket(t, peer)
		for range 3 {
			_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq, flagACK, 10000, nil, nil))
			synctest.Wait()
		}
		packet := peerPacket(t, peer)
		if binary.BigEndian.Uint32(packet.Payload[4:8]) != seq {
			t.Fatal("fallback retransmitted wrong data")
		}
		d := c.DiagnosticSnapshot()
		if d.ConfiguredLossRecovery != "rack-tlp" || d.LossRecovery != "classic" {
			t.Fatalf("fallback not visible: %+v", d)
		}
	})
}

func TestRACKWireReorderingSettlesWithoutRetransmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, c, peer, seq := passiveConfigured(t, 100, 10000, Config{LossRecovery: "rack-tlp"}, false)
		seq = seedRecoveryRTT(t, c, peer, seq)
		mss := uint32(c.mss)
		if _, err := c.Write(make([]byte, 2*c.mss)); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			_ = peerPacket(t, peer)
		}
		time.Sleep(10 * time.Millisecond)
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq, flagACK, 10000, sackOptions(sackBlock{seq + mss, seq + 2*mss}), nil))
		synctest.Wait()
		time.Sleep(time.Millisecond)
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq+2*mss, flagACK, 10000, nil, nil))
		synctest.Wait()
		time.Sleep(100 * time.Millisecond)
		if d := c.DiagnosticSnapshot(); d.Retransmissions != 0 || d.BytesInFlight != 0 {
			t.Fatalf("reordering caused false loss: %+v", d)
		}
	})
}

func TestDSACKWireRestoresBBRAfterSpuriousRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, c, peer, seq := passiveWire(t, 100, 10000, "bbr")
		seq = seedRecoveryRTT(t, c, peer, seq)
		mss := uint32(c.mss)
		if _, err := c.Write(make([]byte, 4*c.mss)); err != nil {
			t.Fatal(err)
		}
		for range 4 {
			_ = peerPacket(t, peer)
		}
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq, flagACK, 10000, sackOptions(sackBlock{seq + mss, seq + 4*mss}), nil))
		_ = peerPacket(t, peer)
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq+4*mss, flagACK, 10000, sackOptions(sackBlock{seq, seq + mss}), nil))
		synctest.Wait()
		if d := c.DiagnosticSnapshot(); d.SpuriousRecoveries != 1 || d.BytesInFlight != 0 {
			t.Fatalf("DSACK did not reach BBR undo: %+v", d)
		}
	})
}

func TestRecoveryTailLossLatency(t *testing.T) {
	for _, detector := range []string{"classic", "rack-tlp"} {
		t.Run(detector, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				_, c, peer, seq := passiveConfigured(t, 100, 10000, Config{LossRecovery: detector}, false)
				seq = seedRecoveryRTT(t, c, peer, seq)
				if _, err := c.Write(make([]byte, 64)); err != nil {
					t.Fatal(err)
				}
				_ = peerPacket(t, peer) // Drop the only outstanding data segment.
				start := time.Now()
				select {
				case raw := <-peer.rx:
					packet, err := ParsePacket(raw)
					if err != nil || binary.BigEndian.Uint32(packet.Payload[4:8]) != seq {
						t.Fatal("invalid tail retransmission")
					}
				case <-time.After(2 * time.Second):
					t.Fatal("tail loss did not recover")
				}
				elapsed := time.Since(start)
				expected := time.Second
				if detector == "rack-tlp" {
					expected = 220 * time.Millisecond
				}
				if elapsed != expected {
					t.Fatalf("tail repair after %s, expected %s", elapsed, expected)
				}
				t.Logf("virtual tail-loss repair: detector=%s srtt=10ms delayed-ack-budget=200ms latency=%s", detector, elapsed)
			})
		})
	}
}

func TestRecoveryRetransmitsLostSYN(t *testing.T) {
	for _, detector := range []string{"classic", "rack-tlp"} {
		t.Run(detector, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				local, peer := memoryPair()
				stack, err := New(Config{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, LossRecovery: detector}, local)
				if err != nil {
					t.Fatal(err)
				}
				defer stack.Close()
				done := make(chan net.Conn, 1)
				go func() { c, _ := stack.DialContextTCP(t.Context(), netip.MustParseAddrPort("192.0.2.2:80")); done <- c }()
				syn := peerPacket(t, peer)
				time.Sleep(time.Second)
				retry := peerPacket(t, peer)
				if retry.Payload[13]&flagSYN == 0 || binary.BigEndian.Uint32(retry.Payload[4:8]) != binary.BigEndian.Uint32(syn.Payload[4:8]) {
					t.Fatal("SYN loss did not use RTO before window negotiation")
				}
				source := netip.AddrPortFrom(syn.Destination, 80)
				destination := netip.AddrPortFrom(syn.Source, binary.BigEndian.Uint16(syn.Payload[:2]))
				_ = peer.WritePacket(wireTCP(source, destination, 100, binary.BigEndian.Uint32(syn.Payload[4:8])+1, flagSYN|flagACK, 10000, nil, nil))
				c := <-done
				if c == nil {
					t.Fatal("handshake did not complete after SYN retransmission")
				}
				_ = c.Close()
			})
		})
	}
}
