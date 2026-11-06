package yuhaiin

import (
	"net/netip"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netstate"
)

type testNetworkIter struct{ items []*UnderlyingNetwork }

func (i *testNetworkIter) HasNext() bool            { return len(i.items) > 0 }
func (i *testNetworkIter) Next() *UnderlyingNetwork { n := i.items[0]; i.items = i.items[1:]; return n }

func TestAndroidStableNetworkIdentityAndValidation(t *testing.T) {
	wifi := &UnderlyingNetwork{Handle: 101, InterfaceName: "wlan0", InterfaceIndex: 7, Addresses: "192.0.2.2 2001:db8::2", Available: true, Validated: true}
	cell := &UnderlyingNetwork{Handle: 102, InterfaceName: "rmnet0", InterfaceIndex: 8, Addresses: "198.51.100.2", Available: true}
	read := func(selected int64) netstate.Snapshot {
		t.Helper()
		s, err := underlyingNetworkSnapshot(&testNetworkIter{[]*UnderlyingNetwork{wifi, cell}}, selected)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	m := netstate.NewManager()
	m.Apply(read(101), false)
	p := m.Capture("wlan0", netip.MustParseAddr("192.0.2.2"), 4)
	other := m.Capture("rmnet0", netip.Addr{}, 4)
	wifi.Validated = false
	if e := m.Apply(read(101), false); e.Changes != 0 || !m.Valid(p) {
		t.Fatal("temporary validation loss was classified as a network switch")
	}
	if e := m.Apply(read(102), false); e.Changes&netstate.NetworkChanged == 0 || !m.Valid(p) || !m.Valid(other) {
		t.Fatal("network selection killed still-usable independent sockets")
	}
	// A new Android Network can reuse both the interface name and address.
	wifi.Handle = 103
	m.Apply(read(102), false)
	if m.Valid(p) || !m.Valid(other) {
		t.Fatal("Android Network replacement was not selectively detected")
	}
}

func TestAndroidUnknownSnapshotAndVPNRejected(t *testing.T) {
	for _, raw := range []*UnderlyingNetwork{nil, {Handle: 1, Vpn: true}, {Handle: 1}, {Handle: 1, InterfaceName: "wlan0", Addresses: "bad-address"}} {
		if _, err := underlyingNetworkSnapshot(&testNetworkIter{[]*UnderlyingNetwork{raw}}, 0); err == nil {
			t.Fatalf("unsafe platform snapshot accepted: %+v", raw)
		}
	}
	if _, err := underlyingNetworkSnapshot(nil, 0); err == nil {
		t.Fatal("unknown state became offline")
	}
	if s, err := underlyingNetworkSnapshot(&testNetworkIter{}, 0); err != nil || len(s.Networks) != 0 {
		t.Fatal("authoritative offline snapshot was not accepted")
	}
}
