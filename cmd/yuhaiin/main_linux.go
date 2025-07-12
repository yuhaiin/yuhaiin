//go:build !android

package main

import (
	"errors"
	"syscall"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
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

			log.Error("check mark symbol failed", "err", err)
		}

		return err == nil
	}

	if configuration.ProcessDumper {
		// try start bpf
		netlink.StartBpf()
	}
}
