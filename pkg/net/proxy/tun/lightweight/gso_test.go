package lightweight

import (
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
	"net/netip"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight/congestion"
)

type groupController struct {
	congestion.Controller
	window, rate uint64
}

func (c *groupController) CongestionWindow() uint64           { return c.window }
func (c *groupController) PacingRate() uint64                 { return c.rate }
func (c *groupController) OnPacketSent(congestion.SentPacket) {}

func TestTCPGSOAdmissionLimits(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		window, peer          uint64
		rate                  uint64
		maxSize, budget, want int
	}{
		{"cwnd", 2500, 10000, 0, 65535, 64, 2},
		{"rwnd", 10000, 2500, 0, 65535, 64, 2},
		{"pacing", 10000, 10000, 2500000, 65535, 64, 2},
		{"packet-size", 10000, 10000, 0, 2540, 64, 2},
		{"work-budget", 10000, 10000, 0, 65535, 2, 2},
		{"whole-owner", 10000, 10000, 0, 65535, 64, 6},
		{"one-wire-segment", 1000, 10000, 0, 65535, 64, 0},
		{"no-offload", 10000, 10000, 0, 0, 64, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Stack{config: Config{MemoryLimit: 1 << 20}, done: make(chan struct{}), headroom: 10, gsoMax: tc.maxSize}
			s.initOutput(trafficcontrol.SchedulerFIFO, 1, 1<<20)
			s.buffers.init(s)
			s.buffers.cacheLimit = 0
			owner, err := s.buffers.get(6000)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.release()
			c := &TCPConn{stack: s, key: flowKey{local: netip.MustParseAddrPort("192.0.2.1:1000"), remote: netip.MustParseAddrPort("192.0.2.2:2000")}, state: Established, mss: 1000, pathMSS: 1460, sndUna: 1, sndNxt: 1, sndEnd: 6001, peerWindow: uint32(tc.peer), receiveLimit: 65535, controller: &groupController{window: tc.window, rate: tc.rate}}
			for i := range 6 {
				c.tx.push(&sendSegment{seq: 1 + uint32(i*1000), flags: flagACK, data: owner.data[i*1000 : (i+1)*1000], owner: owner})
			}
			if got := c.transmitGroup(0, time.Now(), tc.budget); got != tc.want {
				t.Fatalf("sent=%d want=%d", got, tc.want)
			}
			if tc.want == 0 {
				if s.output.Stats().Packets != 0 {
					t.Fatal("unexpected GSO record")
				}
				return
			}
			packet, ok := s.output.Dequeue(false)
			if !ok {
				t.Fatal("missing output packet")
			}
			defer packet.release()
			if packet.offset != 10 || packet.segmentSize != 1000 || len(packet.data)-packet.offset != 40+1000*tc.want {
				t.Fatalf("invalid group metadata: offset=%d MSS=%d length=%d", packet.offset, packet.segmentSize, len(packet.data))
			}
			if c.flight() != uint64(tc.want*1000) || c.sndNxt != uint32(1+tc.want*1000) {
				t.Fatalf("invalid logical accounting: flight=%d next=%d", c.flight(), c.sndNxt)
			}
			if got := c.nextSendIndex(); got != tc.want {
				t.Fatalf("next=%d want=%d", got, tc.want)
			}
			c.tx.values()[0].lossReported = true
			c.repairPending = true
			if got := c.nextSendIndex(); got != 0 {
				t.Fatalf("lost descriptor skipped: %d", got)
			}
			c.tx.values()[0].lossReported = false
			if got := c.nextSendIndex(); got != tc.want || c.repairPending {
				t.Fatalf("repair scan not retired: next=%d pending=%v", got, c.repairPending)
			}
		})
	}
}
