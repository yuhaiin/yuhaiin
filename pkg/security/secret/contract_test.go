package secret_test

import (
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/security/secret"
)

func TestProtocolCredentialsAndKeysNeverAppearInMaskedJSON(t *testing.T) {
	value := struct {
		Node    node.Node
		Inbound inbound.Inbound
	}{
		Node: node.Node{Chain: []node.Protocol{
			{Type: "vmess", Vmess: &node.Vmess{UUID: "reusable-proof-vmess"}},
			{Type: "hysteria2", Hysteria2: &node.Hysteria2{Auth: "reusable-proof-auth", SalamanderPassword: "reusable-proof-obfs"}},
			{Type: "ssh", SSH: &node.SSH{Password: "reusable-proof-password", PrivateKey: "reusable-proof-private", PrivateKeyPassphrase: "reusable-proof-passphrase", HostKey: "public-pin"}},
			{Type: "wireguard", Wireguard: &node.Wireguard{SecretKey: "reusable-proof-wg", Peers: []node.WireguardPeer{{PublicKey: "public-peer", PreSharedKey: "reusable-proof-psk"}}}},
			{Type: "nebula", Nebula: &node.Nebula{ConfigYAML: "reusable-proof-yaml"}},
		}},
		Inbound: inbound.Inbound{Protocol: inbound.NewTypedProtocol(inbound.HTTPProtocol{Username: "operator", Password: "reusable-proof-inbound"}), Transports: []inbound.Transport{inbound.NewTypedTransport(inbound.TLSAutoTransport{CAKeyBase64: []byte("private-key-bytes")})}},
	}
	masked, err := secret.Redact(value)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(masked)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "reusable-proof") || strings.Contains(string(encoded), "cHJpdmF0ZS1rZXktYnl0ZXM=") {
		t.Fatal("a typed protocol field exposed a proof")
	}
	if !strings.Contains(string(encoded), "public-peer") || !strings.Contains(string(encoded), "public-pin") {
		t.Fatal("public key metadata was unnecessarily removed")
	}
}

func TestGatewayHeaderProofCannotBePublishedByChangingItsDiscriminator(t *testing.T) {
	old := gateway.Condition{Field: "header", Key: "Authorization", Values: []string{"Bearer private-proof"}}
	masked, err := secret.Redact(old)
	if err != nil || !strings.HasPrefix(masked.Values[0], secret.Preserved) {
		t.Fatal("header condition leaked a proof", err)
	}
	masked.Field = "host"
	for _, capabilities := range []secret.Capabilities{{}, {Manage: true}} {
		if _, err := secret.Merge(secret.WithCapabilities(t.Context(), capabilities), masked, old); !errors.Is(err, secret.ErrPreserved) {
			t.Fatal("preserved secret became public match metadata", err)
		}
	}
}
