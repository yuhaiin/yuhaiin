package device

import (
	"os/exec"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
)

type Opt struct {
	*listener.Tun
	*netlink.Options
	netapi.Handler
}

func (o *Opt) PostDown() {
	execPost(o.Tun.GetPostDown())
}

func (o *Opt) PostUp() {
	execPost(o.Tun.GetPostUp())
}

func execPost(cmd []string) {
	if len(cmd) == 0 {
		return
	}
	output, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
	if err != nil {
		log.Error("execPost", "err", err)
		return
	}

	log.Info("execPost", "cmd", cmd, "output", string(output))
}
