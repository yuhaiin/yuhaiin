package inbound

import (
	json "encoding/json/v2"
	"testing"
)

func TestMasqueTaggedInbound(t *testing.T) {
	p := NewTypedProtocol(MasqueProtocol{
		AuthToken: "test",
		ServerAddresses: []string{"10.88.0.1/32"},
		ClientAddresses: []string{"10.88.0.2/32"},
	})
	if p.Type != ProtocolMasque || p.Masque == nil {
		t.Fatalf("tagged inbound: %+v", p)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Protocol
	if err := json.Unmarshal(data, &decoded); err != nil || decoded.Masque == nil {
		t.Fatalf("decode tagged inbound: %s: %v", data, err)
	}
}
