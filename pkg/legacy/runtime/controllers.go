package legacyruntime

import (
	"context"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	nodemanager "github.com/Asutorufa/yuhaiin/pkg/node"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

func RegisterNodeRuntime(manager *nodemanager.Manager) {
	register.RegisterContractPoint("point_as_endpoint", func(config contractnode.PointAsEndpoint, _ netapi.Proxy) (netapi.Proxy, error) {
		return manager.Outbound().GetDialerByID(context.Background(), config.Hash)
	})
	register.RegisterContractPoint("set", func(config contractnode.Set, _ netapi.Proxy) (netapi.Proxy, error) {
		return nodemanager.NewContractSet(config.Nodes, config.Strategy, manager)
	})
}
