package bbr

import (
	"testing"

	"github.com/apernet/quic-go/congestion"
)

func TestRingBufferShrinkKeepsOrderAcrossWrap(t *testing.T) {
	var r RingBuffer[int]
	r.Init(4)
	for i := range 64 {
		r.PushBack(i)
	}
	// Leave a wrapped window of 6 elements in a 64-slot ring.
	for range 60 {
		r.PopFront()
	}
	for i := 64; i < 66; i++ {
		r.PushBack(i)
	}
	r.shrink(4)
	if len(r.ring) != 32 {
		t.Fatalf("capacity = %d, want 32", len(r.ring))
	}
	if r.Len() != 6 {
		t.Fatalf("len = %d, want 6", r.Len())
	}
	for want := 60; want < 66; want++ {
		if got := r.PopFront(); got != want {
			t.Fatalf("PopFront = %d, want %d", got, want)
		}
	}
	if !r.Empty() {
		t.Fatal("ring not empty after draining")
	}
	r.PushBack(1)
	if r.Front() == nil || *r.Front() != 1 {
		t.Fatal("ring unusable after shrink")
	}
}

func TestRingBufferShrinkRespectsThresholdAndMinimum(t *testing.T) {
	var r RingBuffer[int]
	r.Init(8)
	for i := range 64 {
		r.PushBack(i)
	}
	for range 47 {
		r.PopFront()
	}
	r.shrink(8) // 17 of 64 used: above a quarter, keep capacity
	if len(r.ring) != 64 {
		t.Fatalf("shrunk while more than a quarter used: %d", len(r.ring))
	}
	for !r.Empty() {
		r.PopFront()
	}
	for range 10 {
		r.shrink(8)
	}
	if len(r.ring) != 8 {
		t.Fatalf("capacity = %d, want minimum 8", len(r.ring))
	}
}

func TestPacketNumberIndexedQueueReleasesBurstCapacity(t *testing.T) {
	q := newPacketNumberIndexedQueue[int](defaultConnectionStateMapQueueSize)
	const burst = 16384
	for pn := congestion.PacketNumber(1); pn <= burst; pn++ {
		v := int(pn)
		if !q.Emplace(pn, &v) {
			t.Fatalf("Emplace(%d) failed", pn)
		}
	}
	peak := len(q.entries.ring)
	if peak < burst {
		t.Fatalf("peak capacity %d < burst %d", peak, burst)
	}
	// Acknowledge everything but the newest few packets.
	for pn := congestion.PacketNumber(1); pn <= burst-4; pn++ {
		if !q.Remove(pn, nil) {
			t.Fatalf("Remove(%d) failed", pn)
		}
	}
	if got := len(q.entries.ring); got > peak/2 {
		t.Fatalf("capacity stayed at %d after ACKs (peak %d)", got, peak)
	}
	for pn := congestion.PacketNumber(burst - 3); pn <= burst; pn++ {
		if e := q.GetEntry(pn); e == nil || *e != int(pn) {
			t.Fatalf("GetEntry(%d) = %v after shrink", pn, e)
		}
	}
	q.RemoveUpTo(burst + 1)
	if got := len(q.entries.ring); got != defaultConnectionStateMapQueueSize {
		t.Fatalf("capacity = %d after drain, want %d", got, defaultConnectionStateMapQueueSize)
	}
}
