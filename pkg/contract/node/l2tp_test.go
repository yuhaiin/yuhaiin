package node

import (
	"encoding/json/v2"
	"reflect"
	"testing"
)

func TestL2TPContracts(t *testing.T) {
	for _, original := range []Protocol{
		{Type: "l2tp", L2TP: &L2TP{Gateway: "vpn.example:1701", AuthType: "mschap-v2", Username: "alice", Password: "secret", SharedSecret: "tunnel-secret", IPv6: true, IPv6Address: "fd88::2/64", MTU: 1400, AutoReconnect: true}},
		{Type: "l2tpv3", L2TPv3: &L2TPv3{Gateway: "vpn.example:1701", LocalAddress: "0.0.0.0:1701", Static: true, LocalSessionID: 4294967295, PeerSessionID: 200, LocalCookie: "11223344", PeerCookie: "aabbccddeeff0011", Sublayer: true, Address: "10.89.0.2/24", Router: "10.89.0.1", IPv6Address: "fd89::2/64", IPv6Router: "fd89::1", MTU: 1400}},
	} {
		p := original
		blob, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		var decoded Protocol
		if err := json.Unmarshal(blob, &decoded); err != nil {
			t.Fatal(err)
		}
		if err := decoded.Validate(); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(decoded, p) {
			t.Fatalf("contract changed: %s", blob)
		}
		decoded.OpenVPN = &OpenVPN{}
		if decoded.Validate() == nil {
			t.Fatal("accepted multiple protocol configurations")
		}
	}
}
