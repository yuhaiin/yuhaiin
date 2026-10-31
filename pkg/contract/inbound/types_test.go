package inbound

import (
	json "encoding/json/v2"
	"strings"
	"testing"
)

func TestTunStackJSONCompatibility(t *testing.T) {
	var old TunProtocol
	if err := json.Unmarshal([]byte(`{"driver":"channel","name":"tun://test"}`), &old); err != nil {
		t.Fatal(err)
	}
	if old.Stack != "" || old.CongestionControl != "" {
		t.Fatal("legacy config opted into new stack")
	}
	configured := TunProtocol{Driver: "channel", Stack: "lightweight", CongestionControl: "bbr"}
	b, err := json.Marshal(configured)
	if err != nil {
		t.Fatal(err)
	}
	var got TunProtocol
	if err = json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Stack != "lightweight" || got.CongestionControl != "bbr" || got.Driver != "channel" {
		t.Fatalf("roundtrip: %+v", got)
	}
}

func TestProtocolTaggedObjectJSON(t *testing.T) {
	var protocol Protocol
	if err := json.Unmarshal([]byte(`{"type":"reverse_tcp","reverse_tcp":{"target":"127.0.0.1:3000"}}`), &protocol); err != nil {
		t.Fatal(err)
	}

	if err := protocol.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := protocol.ReverseTCP.Target; got != "127.0.0.1:3000" {
		t.Fatalf("ReverseTCP.Target = %q", got)
	}

	data, err := json.Marshal(protocol)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"config"`) {
		t.Fatalf("tagged object json must not contain config wrapper: %s", data)
	}
	if !strings.Contains(string(data), `"reverse_tcp"`) {
		t.Fatalf("tagged object json missing reverse_tcp field: %s", data)
	}
}

func TestTaggedObjectRejectsMismatchedField(t *testing.T) {
	var protocol Protocol
	if err := json.Unmarshal([]byte(`{"type":"reverse_tcp","mixed":{}}`), &protocol); err != nil {
		t.Fatal(err)
	}

	if err := protocol.Validate(); err == nil {
		t.Fatal("Validate succeeded for mismatched type and concrete field")
	}
}

func TestRemovedReverseHTTPProtocolIsRejected(t *testing.T) {
	var protocol Protocol
	if err := json.Unmarshal([]byte(`{"type":"reverse_http","reverse_http":{"url":"http://127.0.0.1:3000"}}`), &protocol); err != nil {
		t.Fatal(err)
	}
	if err := protocol.Validate(); err == nil {
		t.Fatal("removed reverse_http protocol accepted")
	}
}

func TestInboundValidateRejectsDuplicateConcreteFields(t *testing.T) {
	inbound := Inbound{
		ID:      "mixed",
		Enabled: true,
		Network: Network{
			Type:   NetworkTCPUDP,
			TCPUDP: &TCPUDPNetwork{Host: ":9002", UDP: UDPEnabled},
			Empty:  &EmptyNetwork{},
		},
		Protocol: Protocol{
			Type:  ProtocolMixed,
			Mixed: &MixedProtocol{},
		},
	}

	if err := inbound.Validate(); err == nil {
		t.Fatal("Validate succeeded with duplicate network concrete fields")
	}
}

func TestNewTypedTaggedObjects(t *testing.T) {
	network := NewTypedNetwork(TCPUDPNetwork{Host: ":9002", UDP: UDPEnabled})
	if network.Type != NetworkTCPUDP || network.TCPUDP == nil || network.TCPUDP.Host != ":9002" {
		t.Fatalf("unexpected network: %#v", network)
	}

	protocol := NewTypedProtocol(&ReverseTCPProtocol{Target: "127.0.0.1:3000"})
	if protocol.Type != ProtocolReverseTCP || protocol.ReverseTCP == nil || protocol.ReverseTCP.Target != "127.0.0.1:3000" {
		t.Fatalf("unexpected protocol: %#v", protocol)
	}

	var normal *NormalTransport
	transport := NewTypedTransport(normal)
	if transport.Type != TransportNormal || transport.Normal == nil {
		t.Fatalf("unexpected transport: %#v", transport)
	}
}

func TestTunAutoFakeIPRouteJSONCompatibility(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		original := NewTypedProtocol(TunProtocol{AutoFakeIPRoute: enabled, Routes: []string{"192.0.2.0/24"}})
		data, err := json.Marshal(original)
		if err != nil {
			t.Fatal(err)
		}
		var decoded Protocol
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Tun.AutoFakeIPRoute != enabled || decoded.Tun.Routes[0] != "192.0.2.0/24" {
			t.Fatalf("bad round trip: %s", data)
		}
	}
	var old Protocol
	if err := json.Unmarshal([]byte(`{"type":"tun","tun":{"routes":["198.18.0.0/16"]}}`), &old); err != nil {
		t.Fatal(err)
	}
	if old.Tun.AutoFakeIPRoute {
		t.Fatal("old config was automatically enabled")
	}
}

func TestDarwinTunBatchJSONCompatibility(t *testing.T) {
	var legacy TunProtocol
	if err := json.Unmarshal([]byte(`{"name":"tun://utun8","mtu":1500}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.Darwin.ExperimentalBatch {
		t.Fatal("legacy config enabled experiment")
	}
	for _, enabled := range []bool{false, true} {
		want := TunProtocol{Darwin: DarwinTunOptions{ExperimentalBatch: enabled, BatchSize: 64, PendingPackets: 128}}
		data, err := json.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), `"experimentalBatch":`) {
			t.Fatal("wrong API field", string(data))
		}
		var got TunProtocol
		if err = json.Unmarshal(data, &got); err != nil || got.Darwin != want.Darwin {
			t.Fatal(got, err)
		}
	}
}

func TestSSTPRejectsLegacyAuthentication(t *testing.T) {
	for _, authentication := range []*Authentication{nil, {Mode: "legacy"}} {
		inbound := Inbound{Protocol: Protocol{Type: ProtocolSSTP}, Authentication: authentication}
		if err := inbound.Validate(); err == nil || !strings.Contains(err.Error(), "sstp inbound requires user authentication") {
			t.Fatal("SSTP accepted a configuration without a scoped identity", err)
		}
	}
}
