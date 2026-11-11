package peerrendezvous

import (
	"net/netip"
	"testing"
	"time"
)

func testCoordinator(key [32]byte) *Coordinator {
	return &Coordinator{
		cookieKey: [32]byte{8},
		pairs:     map[[16]byte]*pair{pairID(key): {key: key}},
	}
}

func testHello(key [32]byte, role Role) message {
	var m message
	copy(m[:4], magic)
	m[4], m[5], m[39] = hello, byte(role), 3
	id := pairID(key)
	copy(m[8:24], id[:])
	m.sign(key)
	return m
}

func TestRendezvousRequiresReturnReachabilityAndExpires(t *testing.T) {
	now := time.Unix(100, 0)
	first := netip.MustParseAddrPort("[2001:db8::1]:2001")
	second := netip.MustParseAddrPort("[2001:db8::2]:2002")
	key := [32]byte{1}
	c := testCoordinator(key)
	p := c.pairs[pairID(key)]

	m := testHello(key, Dialer)
	bad := m
	bad[95] ^= 1
	if c.handle(&bad, messageSize, first, now) || c.handle(&m, messageSize+1, first, now) {
		t.Fatal("accepted malformed or unauthenticated request")
	}
	if !c.handle(&m, messageSize, first, now) || m.kind() != challenge || !m.valid(key) || p.peers[Dialer].endpoint.IsValid() {
		t.Fatal("hello must return a challenge without registering the source")
	}
	m[4] = confirm
	m.sign(key)
	replay := m
	if c.handle(&replay, messageSize, second, now) {
		t.Fatal("challenge accepted from a different UDP address")
	}
	if !c.handle(&m, messageSize, first, now.Add(cookiePeriod)) || m.kind() != discovered ||
		m.endpoint().IsValid() || p.peers[Dialer].endpoint != first {
		t.Fatal("valid confirmation across a cookie bucket must register the source")
	}
	registerPublisher := func(at time.Time) netip.AddrPort {
		t.Helper()
		m := testHello(key, Publisher)
		if !c.handle(&m, messageSize, second, at) {
			t.Fatal("missing publisher challenge")
		}
		m[4] = confirm
		m.sign(key)
		if !c.handle(&m, messageSize, second, at) || m.kind() != discovered || !m.valid(key) {
			t.Fatal("missing publisher discovery response")
		}
		return m.endpoint()
	}
	if endpoint := registerPublisher(now.Add(cookiePeriod)); endpoint != first {
		t.Fatalf("discovered %v, want %v", endpoint, first)
	}
	if endpoint := registerPublisher(now.Add(cookiePeriod + peerTTL)); endpoint.IsValid() {
		t.Fatalf("expired endpoint advertised: %v", endpoint)
	}
	if c.handle(&replay, messageSize, first, now.Add(2*cookiePeriod)) {
		t.Fatal("accepted expired confirmation")
	}
}

func BenchmarkCoordinatorRegistration(b *testing.B) {
	key := [32]byte{1}
	c := testCoordinator(key)
	from := netip.MustParseAddrPort("192.0.2.1:2001")
	request := testHello(key, Dialer)
	now := time.Unix(100, 0)
	b.ReportAllocs()
	for b.Loop() {
		m := request
		if !c.handle(&m, messageSize, from, now) {
			b.Fatal("hello rejected")
		}
		m[4] = confirm
		m.sign(key)
		if !c.handle(&m, messageSize, from, now) {
			b.Fatal("confirmation rejected")
		}
	}
}

func BenchmarkCoordinatorLookup(b *testing.B) {
	key := [32]byte{1}
	c := testCoordinator(key)
	from := netip.MustParseAddrPort("192.0.2.1:2001")
	request := testHello(key, Dialer)
	request[6] = lookupFlag
	request.sign(key)
	now := time.Unix(100, 0)
	b.ReportAllocs()
	for b.Loop() {
		m := request
		if !c.handle(&m, messageSize, from, now) {
			b.Fatal("lookup challenge rejected")
		}
		m[4] = confirm
		m.sign(key)
		if !c.handle(&m, messageSize, from, now) {
			b.Fatal("lookup confirmation rejected")
		}
	}
}
