package secret_test

import (
	"github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/security/secret"
	"strconv"
	"testing"
)

func BenchmarkSecretConfiguration(b *testing.B) {
	original := node.Node{ID: "node", Name: "Example", Origin: "manual", Enabled: true, Chain: []node.Protocol{{Type: "shadowsocks", Shadowsocks: &node.Shadowsocks{Method: "aes-128-gcm", Password: "private-password"}}}}
	b.Run("MaskNode", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := secret.Redact(original); err != nil {
				b.Fatal(err)
			}
		}
	})
	masked, err := secret.Redact(original)
	if err != nil {
		b.Fatal(err)
	}
	masked.Name = "Renamed"
	ctx := secret.WithCapabilities(b.Context(), secret.Capabilities{})
	b.Run("PreserveNode", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := secret.Merge(ctx, masked, original); err != nil {
				b.Fatal(err)
			}
		}
	})
	nodes := make([]node.Node, 1024)
	for i := range nodes {
		nodes[i] = original
		nodes[i].ID = strconv.Itoa(i)
	}
	b.Run("Mask1024Nodes", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := secret.Redact(nodes); err != nil {
				b.Fatal(err)
			}
		}
	})
}
