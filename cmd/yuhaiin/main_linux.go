package main

import (
	"errors"
	"log/slog"
	"syscall"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
)

func init() {
	var disabledMark bool
	dialer.DefaultMarkSymbol = func(socket int32) bool {
		if disabledMark {
			return false
		}

		err := dialer.LinuxMarkSymbol(socket, 0x00000500)
		if err != nil {
			if errors.Is(err, syscall.EPERM) {
				slog.Info("check mark symbol no permission, disable it")
				disabledMark = true
				return false
			}

			slog.Error("check mark symbol failed", slog.Any("err", err))
		}

		return err == nil
	}
}
