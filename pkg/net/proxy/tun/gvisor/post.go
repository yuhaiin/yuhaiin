package tun

import (
	"os/exec"

	"github.com/Asutorufa/yuhaiin/pkg/log"
)

func (o *Opt) PostDown() {
	execPost(o.Inbound_Tun.Tun.PostDown)
}

func (o *Opt) PostUp() {
	execPost(o.Inbound_Tun.Tun.PostUp)
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
