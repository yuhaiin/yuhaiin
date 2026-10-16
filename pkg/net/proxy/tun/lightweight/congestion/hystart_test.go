package congestion

import (
	"testing"
	"time"
)

type slowStartDriver struct {
	c     Controller
	acked uint32
	now   time.Time
}

func (d *slowStartDriver) ack(rtt time.Duration) {
	d.acked += 1000
	d.now = d.now.Add(time.Millisecond)
	end := (d.acked/8000 + 1) * 8000
	d.c.OnAck(AckEvent{Now: d.now, AckedBytes: 1000, RTT: rtt, ACK: d.acked, NextSeq: end, BytesInFlight: d.c.CongestionWindow()})
}
func (d *slowStartDriver) round(rtt time.Duration) {
	for range 8 {
		d.ack(rtt)
	}
}
func TestHyStartCSSAndSpuriousExit(t *testing.T) {
	for _, kind := range []string{"reno", "cubic"} {
		t.Run(kind, func(t *testing.T) {
			c, err := New(kind, Config{MSS: 1000})
			if err != nil {
				t.Fatal(err)
			}
			d := slowStartDriver{c: c, now: time.Unix(100, 0)}
			d.round(100 * time.Millisecond)
			d.round(120 * time.Millisecond)
			before := c.CongestionWindow()
			d.ack(120 * time.Millisecond)
			if c.CongestionWindow()-before != 250 {
				t.Fatalf("CSS growth=%d, want 250 bytes", c.CongestionWindow()-before)
			}
			d.round(100 * time.Millisecond)
			before = c.CongestionWindow()
			d.ack(100 * time.Millisecond)
			if c.CongestionWindow()-before != 1000 {
				t.Fatal("RTT recovery failed to resume standard slow start")
			}
		})
	}
}
func TestHyStartPersistentDelayExitsAfterFiveCSSRounds(t *testing.T) {
	for _, kind := range []string{"reno", "cubic"} {
		t.Run(kind, func(t *testing.T) {
			c, _ := New(kind, Config{MSS: 1000})
			d := slowStartDriver{c: c, now: time.Unix(100, 0)}
			d.round(100 * time.Millisecond)
			d.round(120 * time.Millisecond)
			for range 4 {
				d.round(120 * time.Millisecond)
			} // Entering partial round counts as the first.
			before := c.CongestionWindow()
			d.ack(120 * time.Millisecond)
			if c.CongestionWindow()-before >= 250 {
				t.Fatal("five CSS rounds failed to enter congestion avoidance")
			}
		})
	}
}
func TestHyStartMinimumDelayThreshold(t *testing.T) {
	for _, kind := range []string{"reno", "cubic"} {
		t.Run(kind, func(t *testing.T) {
			c, _ := New(kind, Config{MSS: 1000})
			d := slowStartDriver{c: c, now: time.Unix(100, 0)}
			d.round(2 * time.Millisecond)
			d.round(5 * time.Millisecond)
			before := c.CongestionWindow()
			d.ack(5 * time.Millisecond)
			if c.CongestionWindow()-before != 1000 {
				t.Fatal("sub-4ms RTT inflation caused premature CSS")
			}
		})
	}
}

func TestHyStartInvalidRTTDoesNotSupplyRequiredSamples(t *testing.T) {
	for _, kind := range []string{"reno", "cubic"} {
		t.Run(kind, func(t *testing.T) {
			c, _ := New(kind, Config{MSS: 1000})
			d := slowStartDriver{c: c, now: time.Unix(100, 0)}
			d.round(100 * time.Millisecond)
			for range 7 {
				d.ack(120 * time.Millisecond)
			}
			d.ack(0) // Karn excluded an ambiguous retransmission sample.
			before := c.CongestionWindow()
			d.ack(120 * time.Millisecond)
			if c.CongestionWindow()-before != 1000 {
				t.Fatal("invalid RTT triggered CSS with fewer than eight samples")
			}
		})
	}
}
func TestHyStartSequenceWrap(t *testing.T) {
	for _, kind := range []string{"reno", "cubic"} {
		t.Run(kind, func(t *testing.T) {
			c, _ := New(kind, Config{MSS: 1000})
			base := uint32(0xfffff000)
			for round := range 2 {
				rtt := 100 * time.Millisecond
				if round == 1 {
					rtt = 120 * time.Millisecond
				}
				for i := range 8 {
					ack := base + uint32(round*8000+(i+1)*1000)
					next := base + uint32((round+1)*8000)
					if i == 7 {
						next += 8000
					}
					c.OnAck(AckEvent{AckedBytes: 1000, RTT: rtt, ACK: ack, NextSeq: next})
				}
			}
			before := c.CongestionWindow()
			c.OnAck(AckEvent{AckedBytes: 1000, RTT: 120 * time.Millisecond, ACK: base + 17000, NextSeq: base + 24000})
			if c.CongestionWindow()-before != 250 {
				t.Fatal("sequence wrap broke HyStart++ round tracking")
			}
		})
	}
}
