package system

import (
	"os/exec"

	"github.com/Asutorufa/yuhaiin/pkg/log"
)

func RefreshCache() {
	output, err := exec.Command("dscacheutil", "-flushcache").CombinedOutput()
	if err != nil {
		log.Warn("refresh dns cache failed", "err", err, "output", string(output))
	} else {
		log.Info("refresh dns cache success", "output", string(output))
	}

	output, err = exec.Command("killall", "-HUP", "mDNSResponder").CombinedOutput()
	if err != nil {
		log.Warn("killall -HUP mDNSResponder failed", "err", err, "output", string(output))
	} else {
		log.Info("killall -HUP mDNSResponder success", "output", string(output))
	}
}
