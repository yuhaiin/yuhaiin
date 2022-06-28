//go:build linux
// +build linux

package server

import (
	"fmt"
	"log"
	"syscall"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
)

func control(fd uintptr) error {
	if dialer.DefaultRoutingMark != 0 {
		v, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK)
		log.Println("dialer: get socket option: SO_MARK", v, err)
		if err == nil && v == dialer.DefaultRoutingMark {
			return fmt.Errorf("cycle dial is not allow")
		}
	}

	return nil
}
