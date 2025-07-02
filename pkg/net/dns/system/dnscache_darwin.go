package system

import (
	"log/slog"
	"os/exec"
)

func RefreshCache() {
	output, err := exec.Command("dscacheutil", "-flushcache").CombinedOutput()
	if err != nil {
		slog.Warn("refresh dns cache failed", "err", err, "output", string(output))
	}

	output, err = exec.Command("killall", "-HUP", "mDNSResponder").CombinedOutput()
	if err != nil {
		slog.Warn("killall -HUP mDNSResponder failed", "err", err, "output", string(output))
	}
}
