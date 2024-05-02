//go:build !darwin && !linux
// +build !darwin,!linux

package server

import (
	"fmt"
	"net"
	"runtime"
)

func (r *redir) handle(req net.Conn) error {
	req.Close()
	return fmt.Errorf("%s can't support redir", runtime.GOOS)
}
