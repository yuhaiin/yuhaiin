package node

import (
	json "encoding/json/v2"
	"testing"
)

func TestSoftEtherTypedContract(t *testing.T) {
	in := SoftEther{
		Gateway:   "vpn.example.org:443",
		Username:  "alice",
		Password:  "secret",
		Hub:       "DEFAULT",
		Address:   "192.168.30.5/24",
		Router:    "192.168.30.1",
		MTU:       1400,
		CACertPEM: "PEM",
	}
	typed, err := NewTypedProtocol(in)
	if err != nil {
		t.Fatal(err)
	}
	if typed.Type != "softether" || typed.SoftEther == nil {
		t.Fatalf("bad typed protocol: %#v", typed)
	}
	if err := typed.Validate(); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(typed)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Protocol
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
	if decoded.SoftEther.Gateway != in.Gateway || decoded.SoftEther.Router != in.Router ||
		decoded.SoftEther.CACertPEM != in.CACertPEM {
		t.Fatalf("round trip: %#v", decoded.SoftEther)
	}
}
