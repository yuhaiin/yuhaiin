//go:build linux && !android && (amd64 || arm64)

package zerotier

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

func TestNewClientStartsWithEmbeddedLibrary(t *testing.T) {
	oldDir := configuration.DataDir.Load()
	configuration.DataDir.Store(t.TempDir())
	t.Cleanup(func() { configuration.DataDir.Store(oldDir) })

	proxy, err := register.ContractDialer(contractnode.Node{
		ID: "zerotier-embedded-smoke", Name: "ZeroTier embedded smoke", Origin: "test",
		Chain: []contractnode.Protocol{{
			Type:     "zerotier",
			ZeroTier: &contractnode.ZeroTier{NetworkID: "8056c2e21c000001"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
}
