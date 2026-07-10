package node

import (
	json "encoding/json/v2"
	"strings"
	"testing"
)

func TestProtocolTaggedObjectJSON(t *testing.T) {
	protocol, err := NewTypedProtocol(Direct{})
	if err != nil {
		t.Fatal(err)
	}
	node := Node{
		ID:      "node-1",
		Name:    "direct",
		Origin:  "manual",
		Enabled: true,
		Chain:   []Protocol{protocol},
	}
	if err := node.Validate(); err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(node)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `"chain":[{"type":"direct","direct":{}}]`) {
		t.Fatalf("unexpected json: %s", text)
	}
	if strings.Contains(text, "protocols") || strings.Contains(text, "case") || strings.Contains(text, "value") {
		t.Fatalf("protobuf-shaped field leaked into json: %s", text)
	}

	var decoded Node
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestProtocolRejectsMismatch(t *testing.T) {
	if err := (Protocol{Type: "direct", Reject: &Reject{}}).Validate(); err == nil {
		t.Fatal("expected mismatch error")
	}
	if err := (Protocol{Type: "direct", Direct: &Direct{}, Reject: &Reject{}}).Validate(); err == nil {
		t.Fatal("expected duplicate concrete object error")
	}
}

func TestNewTypedProtocol(t *testing.T) {
	simple, err := NewTypedProtocol(Simple{Host: "127.0.0.1", Port: 1080})
	if err != nil {
		t.Fatal(err)
	}
	if simple.Type != "simple" || simple.Simple == nil || simple.Simple.Host != "127.0.0.1" {
		t.Fatalf("unexpected simple protocol: %#v", simple)
	}
	if err := simple.Validate(); err != nil {
		t.Fatal(err)
	}

	fixed, err := NewTypedProtocol(Fixed{Host: "127.0.0.1", Port: 1080})
	if err != nil {
		t.Fatal(err)
	}
	if fixed.Type != "fixed" || fixed.Fixed == nil || fixed.Fixed.Host != "127.0.0.1" {
		t.Fatalf("unexpected fixed protocol: %#v", fixed)
	}
	if err := fixed.Validate(); err != nil {
		t.Fatal(err)
	}

	direct, err := NewTypedProtocol(Direct{})
	if err != nil {
		t.Fatal(err)
	}
	if direct.Type != "direct" || direct.Direct == nil {
		t.Fatalf("unexpected direct protocol: %#v", direct)
	}
	if err := direct.Validate(); err != nil {
		t.Fatal(err)
	}

	tls, err := NewTypedProtocol(&TLS{Enable: true, ServerNames: []string{"example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if tls.Type != "tls" || tls.TLS == nil || !tls.TLS.Enable || tls.TLS.ServerNames[0] != "example.com" {
		t.Fatalf("unexpected tls protocol: %#v", tls)
	}

	var mux *Mux
	muxProtocol, err := NewTypedProtocol(mux)
	if err != nil {
		t.Fatal(err)
	}
	if muxProtocol.Type != "mux" || muxProtocol.Mux == nil {
		t.Fatalf("unexpected mux protocol: %#v", muxProtocol)
	}
}
