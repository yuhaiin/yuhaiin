package node

import (
	"encoding/json/v2"
	"reflect"
	"testing"
)

func TestOpenVPNTypedContract(t *testing.T) {
	original := OpenVPN{Gateway: "vpn.example:1194", Network: "tcp", CACertPEM: "ca", ClientCertPEM: "cert", ClientKeyPEM: "key", TLSCryptKey: "static", Username: "alice", Password: "secret", ServerName: "vpn.example", Auth: "SHA256", KeyDirection: new(int32(1)), DataCiphers: []string{"AES-128-GCM"}, MTU: 1400, AutoReconnect: true, RenegotiateSeconds: 3600}
	protocol, err := NewTypedProtocol(original)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(protocol)
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
	if decoded.Type != "openvpn" || decoded.OpenVPN == nil || !reflect.DeepEqual(*decoded.OpenVPN, original) {
		t.Fatalf("round trip failed: %s", blob)
	}
	decoded.GlobalProtect = &GlobalProtect{}
	if decoded.Validate() == nil {
		t.Fatal("multiple protocol variants accepted")
	}
}
