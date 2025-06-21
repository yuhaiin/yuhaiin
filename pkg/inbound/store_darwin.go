package inbound

import (
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/networksetup"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
)

func init() {
	platformInfo = append(platformInfo, func(resp *gc.PlatformInfoResponse) {
		ns, err := networksetup.ListAllNetworkServices()
		if err != nil {
			log.Error("list all network services failed", "err", err)
			return
		}

		resp.SetDarwin(gc.PlatformInfoResponsePlatformDarwin_builder{
			NetworkServices: ns,
		}.Build())
	})
}
