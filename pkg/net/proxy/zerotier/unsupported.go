//go:build !(((((linux && !android) || darwin) && (amd64 || arm64)) || (windows && amd64) || (android && arm64 && cgo)))

package zerotier

import (
	"errors"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

func init() {
	register.RegisterContractPoint("zerotier", func(_ contractnode.ZeroTier, _ netapi.Proxy) (netapi.Proxy, error) {
		return nil, errors.New("zerotier: native bridge is unavailable on this target (Android ARM64 requires CGO and NDK)")
	})
}
