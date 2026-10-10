package node

import (
	json "encoding/json/v2"
	"strings"
	"testing"
)

func TestGlobalProtectTypedContract(t *testing.T) {
	original := GlobalProtect{
		Gateway: "vpn.example.com", Username: "alice", Password: "secret",
		MTU: 1300, CACertPEM: "ca", InsecureSkipVerify: true,
	}
	protocol, err := NewTypedProtocol(original)
	if err != nil {
		t.Fatal(err)
	}
	if protocol.Type != "globalprotect" || protocol.GlobalProtect == nil {
		t.Fatalf("unexpected protocol: %#v", protocol)
	}
	if err := protocol.Validate(); err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(protocol)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(blob), `"globalprotect":`) {
		t.Fatalf("missing globalprotect variant: %s", blob)
	}
	var decoded Protocol
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
	if decoded.GlobalProtect.Gateway != original.Gateway || decoded.GlobalProtect.CACertPEM != original.CACertPEM ||
		decoded.GlobalProtect.InsecureSkipVerify != original.InsecureSkipVerify {
		t.Fatalf("contract round trip lost config: %#v", decoded.GlobalProtect)
	}
}
