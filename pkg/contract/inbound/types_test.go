package inbound

import (
	json "encoding/json/v2"
	"strings"
	"testing"
)

func TestProtocolTaggedObjectJSON(t *testing.T) {
	var protocol Protocol
	if err := json.Unmarshal([]byte(`{"type":"reverse_http","reverse_http":{"url":"http://127.0.0.1:3000"}}`), &protocol); err != nil {
		t.Fatal(err)
	}

	if err := protocol.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := protocol.ReverseHTTP.URL; got != "http://127.0.0.1:3000" {
		t.Fatalf("ReverseHTTP.URL = %q", got)
	}

	data, err := json.Marshal(protocol)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"config"`) {
		t.Fatalf("tagged object json must not contain config wrapper: %s", data)
	}
	if !strings.Contains(string(data), `"reverse_http"`) {
		t.Fatalf("tagged object json missing reverse_http field: %s", data)
	}
}

func TestTaggedObjectRejectsMismatchedField(t *testing.T) {
	var protocol Protocol
	if err := json.Unmarshal([]byte(`{"type":"reverse_http","mixed":{}}`), &protocol); err != nil {
		t.Fatal(err)
	}

	if err := protocol.Validate(); err == nil {
		t.Fatal("Validate succeeded for mismatched type and concrete field")
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

	protocol := NewTypedProtocol(&ReverseHTTPProtocol{URL: "http://127.0.0.1:3000"})
	if protocol.Type != ProtocolReverseHTTP || protocol.ReverseHTTP == nil || protocol.ReverseHTTP.URL != "http://127.0.0.1:3000" {
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
