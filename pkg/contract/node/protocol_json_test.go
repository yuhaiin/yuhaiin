package node

import (
	"encoding/json/v2"
	"reflect"
	"strings"
	"testing"
)

func TestVPNProtocolJSONRoundTrip(t *testing.T) {
	ssh := SSH{User: "alice", Password: "secret", HostKey: "SHA256:abc"}
	nebula := Nebula{ConfigYAML: "pki:\n  ca: embedded\n  cert: embedded\n  key: embedded\n"}
	zerotier := ZeroTier{
		NetworkID: "8056c2e21c000001", Identity: "home", Listen: ":0",
		Moons: []ZeroTierMoon{{ID: "fffffffffffffffe", Seed: "0123456789abcdef"}},
	}
	masque := Masque{Endpoint: "127.0.0.1:443", URL: "https://localhost/ip/", LocalAddresses: []string{"10.88.0.2/32"}}
	globalprotect := GlobalProtect{
		Gateway: "vpn.example.com", Username: "alice", Password: "secret",
		UseESP: true, MTU: 1300, CACertPEM: "ca", InsecureSkipVerify: true,
	}
	openvpn := OpenVPN{
		Gateway: "vpn.example:1194", Network: "tcp", CACertPEM: "ca", ClientCertPEM: "cert", ClientKeyPEM: "key",
		TLSCryptKey: "static", Username: "alice", Password: "secret", ServerName: "vpn.example", Auth: "SHA256",
		KeyDirection: new(int32(1)), DataCiphers: []string{"AES-128-GCM"}, MTU: 1400, AutoReconnect: true, RenegotiateSeconds: 3600,
	}
	softether := SoftEther{
		Gateway: "vpn.example.org:443", Username: "alice", Password: "secret", Hub: "DEFAULT",
		Address: "192.168.30.5/24", Router: "192.168.30.1", MTU: 1400, CACertPEM: "PEM",
		AuthType: "certificate", ClientCertPEM: "client cert", ClientKeyPEM: "client key",
		IPv6Address: "2001:db8::5/64", IPv6Router: "fe80::1", UDPAcceleration: true, AutoReconnect: true,
	}
	l2tp := L2TP{
		Gateway: "vpn.example:1701", AuthType: "mschap-v2", Username: "alice", Password: "secret", SharedSecret: "tunnel-secret",
		IPv6: true, IPv6Address: "fd88::2/64", MTU: 1400, AutoReconnect: true,
	}
	l2tpv3 := L2TPv3{
		Gateway: "vpn.example:1701", LocalAddress: "0.0.0.0:1701", Static: true, LocalSessionID: 4294967295, PeerSessionID: 200,
		LocalCookie: "11223344", PeerCookie: "aabbccddeeff0011", Sublayer: true, Address: "10.89.0.2/24", Router: "10.89.0.1",
		IPv6Address: "fd89::2/64", IPv6Router: "fd89::1", MTU: 1400,
	}
	amneziawg := AmneziaWG{
		SecretKey: "private-key-placeholder", Endpoint: []string{"10.12.0.2/24"}, MTU: 1400,
		H1: "1000-2000", I1: "<r 16>", HeaderProtectionKey: "test-protection-key",
		Peers: []WireguardPeer{{PublicKey: "peer-key-placeholder", Endpoint: "127.0.0.1:51820", AllowedIPs: []string{"0.0.0.0/0"}}},
	}
	for _, tt := range []struct {
		payload ProtocolVariant
		want    Protocol
	}{
		{ssh, Protocol{Type: "ssh", SSH: &ssh}},
		{nebula, Protocol{Type: "nebula", Nebula: &nebula}},
		{zerotier, Protocol{Type: "zerotier", ZeroTier: &zerotier}},
		{masque, Protocol{Type: "masque", Masque: &masque}},
		{globalprotect, Protocol{Type: "globalprotect", GlobalProtect: &globalprotect}},
		{openvpn, Protocol{Type: "openvpn", OpenVPN: &openvpn}},
		{softether, Protocol{Type: "softether", SoftEther: &softether}},
		{l2tp, Protocol{Type: "l2tp", L2TP: &l2tp}},
		{l2tpv3, Protocol{Type: "l2tpv3", L2TPv3: &l2tpv3}},
		{amneziawg, Protocol{Type: "amneziawg", AmneziaWG: &amneziawg}},
	} {
		t.Run(tt.want.Type, func(t *testing.T) {
			protocol, err := NewTypedProtocol(tt.payload)
			if err != nil {
				t.Fatal(err)
			}
			if err := protocol.Validate(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(protocol, tt.want) {
				t.Fatalf("constructor = %#v, want %#v", protocol, tt.want)
			}
			data, err := json.Marshal(protocol)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), `"type":"`+tt.want.Type+`"`) || !strings.Contains(string(data), `"`+tt.want.Type+`":`) {
				t.Fatalf("tagged payload missing: %s", data)
			}
			if tt.want.Type == "amneziawg" && !strings.Contains(string(data), `"header_protection_key":"test-protection-key"`) {
				t.Fatalf("header protection key missing: %s", data)
			}
			var decoded Protocol
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatal(err)
			}
			if err := decoded.Validate(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(decoded, tt.want) {
				t.Fatalf("contract changed after JSON reload: %s", data)
			}
		})
	}
}
