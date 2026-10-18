package node

import (
	json "encoding/json/v2"
	"testing"
)

func TestSSHProtocolJSON(t *testing.T) {
	p, err := NewTypedProtocol(SSH{User: "alice", Password: "secret", HostKey: "SHA256:abc"})
	if err != nil { t.Fatal(err) }
	if err := p.Validate(); err != nil { t.Fatal(err) }
	data, err := json.Marshal(p)
	if err != nil { t.Fatal(err) }
	var decoded Protocol
	if err := json.Unmarshal(data, &decoded); err != nil { t.Fatal(err) }
	if err := decoded.Validate(); err != nil { t.Fatal(err) }
	if decoded.SSH == nil || decoded.SSH.User != "alice" || decoded.SSH.HostKey != "SHA256:abc" {
		t.Fatalf("SSH node protocol did not round-trip: %+v", decoded)
	}
}
