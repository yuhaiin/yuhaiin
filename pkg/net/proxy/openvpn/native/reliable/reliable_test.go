// Adapted from xen0bit/veepin (MIT). See ../THIRD_PARTY_LICENSE.
package reliable

import (
	"bytes"
	"testing"
	"time"
)

func TestSenderWindowLimits(t *testing.T) {
	s := NewSender(2, time.Second)
	if _, ok := s.Queue([]byte("a")); !ok {
		t.Fatal("first queue rejected")
	}
	if _, ok := s.Queue([]byte("b")); !ok {
		t.Fatal("second queue rejected")
	}
	if _, ok := s.Queue([]byte("c")); ok {
		t.Fatal("third queue accepted past the window")
	}
	if s.Ready() {
		t.Error("Ready reported room with a full window")
	}
	s.Ack(0)
	if !s.Ready() {
		t.Error("window did not open after an ACK")
	}
	if _, ok := s.Queue([]byte("c")); !ok {
		t.Fatal("queue rejected after ACK freed a slot")
	}
}

func TestSenderAssignsAscendingIDs(t *testing.T) {
	s := NewSender(8, time.Second)
	for want := range uint32(5) {
		id, ok := s.Queue([]byte{byte(want)})
		if !ok || id != want {
			t.Fatalf("Queue #%d => id=%d ok=%v", want, id, ok)
		}
	}
}

func TestSenderRetransmitsOnTimeout(t *testing.T) {
	s := NewSender(4, 100*time.Millisecond)
	s.Queue([]byte("x"))
	now := time.Now()

	due := s.Due(now)
	if len(due) != 1 || due[0].ID != 0 {
		t.Fatalf("first Due = %+v, want the new message", due)
	}
	// Immediately after, nothing is due again.
	if d := s.Due(now); len(d) != 0 {
		t.Fatalf("message re-sent before timeout: %+v", d)
	}
	// Past the timeout it is retransmitted.
	if d := s.Due(now.Add(150 * time.Millisecond)); len(d) != 1 {
		t.Fatalf("message not retransmitted after timeout: %+v", d)
	}
	// Once acknowledged it stops.
	s.Ack(0)
	if d := s.Due(now.Add(time.Second)); len(d) != 0 {
		t.Fatalf("acked message still retransmitted: %+v", d)
	}
}

func TestSenderNextDue(t *testing.T) {
	s := NewSender(4, 100*time.Millisecond)
	if _, ok := s.NextDue(time.Now()); ok {
		t.Error("NextDue reported work with nothing in flight")
	}
	s.Queue([]byte("x"))
	now := time.Now()
	if wait, ok := s.NextDue(now); !ok || wait != 0 {
		t.Errorf("unsent message NextDue = (%v,%v), want (0,true)", wait, ok)
	}
	s.Due(now)
	wait, ok := s.NextDue(now)
	if !ok || wait <= 0 || wait > 100*time.Millisecond {
		t.Errorf("after send NextDue = (%v,%v), want ~100ms", wait, ok)
	}
}

func TestReceiverInOrderDelivery(t *testing.T) {
	r := NewReceiver()
	if out := r.Receive(0, []byte("zero")); len(out) != 1 || !bytes.Equal(out[0], []byte("zero")) {
		t.Fatalf("id 0 not delivered: %v", out)
	}
	if out := r.Receive(1, []byte("one")); len(out) != 1 || !bytes.Equal(out[0], []byte("one")) {
		t.Fatalf("id 1 not delivered: %v", out)
	}
}

func TestReceiverReordersAndFillsGap(t *testing.T) {
	r := NewReceiver()
	// 2 arrives before 0 and 1: nothing deliverable yet.
	if out := r.Receive(2, []byte("two")); len(out) != 0 {
		t.Fatalf("out-of-order id 2 delivered early: %v", out)
	}
	if out := r.Receive(0, []byte("zero")); len(out) != 1 || string(out[0]) != "zero" {
		t.Fatalf("id 0 delivery = %v", out)
	}
	// 1 fills the gap and releases both 1 and the buffered 2.
	out := r.Receive(1, []byte("one"))
	if len(out) != 2 || string(out[0]) != "one" || string(out[1]) != "two" {
		t.Fatalf("gap fill delivered %v, want [one two]", out)
	}
}

func TestReceiverDedupsButReacks(t *testing.T) {
	r := NewReceiver()
	r.Receive(0, []byte("zero"))
	// A retransmit of an already-delivered id: no re-delivery, but it must be
	// acknowledged again since our earlier ACK was evidently lost.
	if out := r.Receive(0, []byte("zero")); len(out) != 0 {
		t.Fatalf("duplicate id 0 re-delivered: %v", out)
	}
	acks := r.TakeACKs(8)
	if len(acks) != 2 || acks[0] != 0 || acks[1] != 0 {
		t.Fatalf("acks = %v, want [0 0] (original + duplicate)", acks)
	}
}

func TestReceiverTakeACKsBounded(t *testing.T) {
	r := NewReceiver()
	for id := range uint32(5) {
		r.Receive(id, []byte{byte(id)})
	}
	if !r.HasACKs() {
		t.Fatal("HasACKs false after receiving")
	}
	first := r.TakeACKs(2)
	if len(first) != 2 || first[0] != 0 || first[1] != 1 {
		t.Fatalf("first drain = %v, want [0 1]", first)
	}
	rest := r.TakeACKs(8)
	if len(rest) != 3 || rest[0] != 2 || rest[2] != 4 {
		t.Fatalf("second drain = %v, want [2 3 4]", rest)
	}
	if r.HasACKs() {
		t.Error("acks still pending after draining all")
	}
}

// TestReceiverCopiesPayload guards against the receiver aliasing a caller's
// decode buffer: mutating it after Receive must not change delivered bytes.
func TestReceiverCopiesPayload(t *testing.T) {
	r := NewReceiver()
	buf := []byte("mutable")
	out := r.Receive(0, buf)
	copy(buf, "XXXXXXX")
	if string(out[0]) != "mutable" {
		t.Errorf("delivered payload aliased the caller buffer: %q", out[0])
	}
}
