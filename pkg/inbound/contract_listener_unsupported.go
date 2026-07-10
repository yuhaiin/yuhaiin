//go:build !linux

package inbound

import (
	"fmt"
	"runtime"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func contractTProxy(netapi.Listener, netapi.Handler) (netapi.Accepter, error) {
	return nil, fmt.Errorf("tproxy is not supported on %s", runtime.GOOS)
}
