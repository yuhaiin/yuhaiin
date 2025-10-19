package inbound

import (
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/networksetup"
	"github.com/Asutorufa/yuhaiin/pkg/protos/api"
)

func init() {
	platformInfo = append(platformInfo, func(resp *api.PlatformInfoResponse) {
		ns, err := networksetup.ListAllNetworkServices()
		if err != nil {
			log.Error("list all network services failed", "err", err)
			return
		}

		resp.SetDarwin(api.PlatformInfoResponsePlatformDarwin_builder{
			NetworkServices: ns,
		}.Build())
	})
}
