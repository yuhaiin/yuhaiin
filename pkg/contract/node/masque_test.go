package node

import (
	json "encoding/json/v2"
	"testing"
)

func TestMasqueTaggedOutbound(t *testing.T) {
	p, err := NewTypedProtocol(Masque{Endpoint: "127.0.0.1:443", URL: "https://localhost/ip/", LocalAddresses: []string{"10.88.0.2/32"}})
	if err != nil || p.Type != "masque" || p.Masque == nil {
		t.Fatalf("tagged protocol: %+v, %v", p, err)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Protocol
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Masque == nil || decoded.Masque.URL != p.Masque.URL {
		t.Fatalf("roundtrip mismatch: %s", data)
	}
}
