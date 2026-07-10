//go:build linux

package inbound

import (
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tproxy"
)

func contractTProxy(lis netapi.Listener, handler netapi.Handler) (netapi.Accepter, error) {
	return tproxy.NewTproxy(tproxy.ServerConfig{}, lis, handler)
}
