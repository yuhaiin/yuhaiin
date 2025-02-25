package main

import (
	"errors"
	"log/slog"
	"syscall"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
)

func init() {
	var disabledMark bool
	dialer.DefaultMarkSymbol = func(socket int32) bool {
		if disabledMark {
			return false
		}

		err := dialer.LinuxMarkSymbol(socket, device.Mark)
		if err != nil {
			if errors.Is(err, syscall.EPERM) {
				log.Info("check mark symbol no permission, disable it")
				disabledMark = true
				return false
			}

			log.Error("check mark symbol failed", slog.Any("err", err))
		}

		return err == nil
	}
}
