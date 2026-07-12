package legacyruntime

import (
	"context"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	nodepkg "github.com/Asutorufa/yuhaiin/pkg/node"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

func RegisterNodeRuntime(runtime *nodepkg.NodeRuntime) {
	register.RegisterContractPoint("point_as_endpoint", func(config contractnode.PointAsEndpoint, _ netapi.Proxy) (netapi.Proxy, error) {
		return runtime.GetDialerByID(context.Background(), config.Hash)
	})
	register.RegisterContractPoint("set", func(config contractnode.Set, _ netapi.Proxy) (netapi.Proxy, error) {
		return nodepkg.NewContractSet(config.Nodes, config.Strategy, runtime)
	})
}
